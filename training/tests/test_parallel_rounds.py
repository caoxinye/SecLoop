# SPDX-License-Identifier: Apache-2.0
"""Concurrency tests for the SA-GRPO cascade reward.

The SOC transport and the penalty judge are replaced through the module-level seams of
:mod:`open_r1.rewards`.  The fake executor sleeps to emulate a round, so every test here
runs without a SOC server, a VM or a network request.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from pathlib import Path

import pytest

TRAINING_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRAINING_ROOT / "src"))

from open_r1 import rewards  # noqa: E402  (import after sys.path setup)

#: Emulated duration of one SOC round.  Long enough for worker threads to overlap, short
#: enough that the whole file stays fast.
ROUND_S = 0.2

TOOL_NAMES = ["block_ip"]


def completion(ip: str) -> list:
    """A TRL-shaped completion whose strategy is ``block_ip <ip>``."""
    strategy = json.dumps([{"tool": "block_ip", "params": {"ip": ip}}])
    return [{"role": "assistant", "content": strategy}]


def fake_parse(text: str):
    """Minimal parser mirrored on the shared one: emit ``{tool, params}`` objects."""
    parsed = json.loads(text)
    if isinstance(parsed, dict) and "tool" in parsed:
        parsed = [parsed]
    if not isinstance(parsed, list) or not parsed:
        raise ValueError("empty tool-call strategy")
    return [{"tool": item.get("tool"), "params": item.get("params") or {}} for item in parsed]


class FakeToolManager:
    """Minimal stand-in for the agent's authoritative ToolManager."""

    def get_available_tools(self) -> list:
        return list(TOOL_NAMES)


def _index_of(ip: str) -> int:
    """Recover the completion index encoded in the documentation-IP last octet."""
    return int(ip.rsplit(".", 1)[1]) - 1


class FakeRound:
    """A fake SOC round: sleeps, tracks concurrent rounds and returns a feedback vector."""

    def __init__(self, delay_for, attack_for=None, retryable_for=None):
        self._delay_for = delay_for
        self._attack_for = attack_for or (lambda ip: 0.0)
        self._retryable_for = retryable_for or (lambda ip: False)
        self._lock = threading.Lock()
        self.calls: list = []
        self.in_flight = 0
        self.max_in_flight = 0

    def execute_strategy(self, strategy, *args, **kwargs):
        ip = strategy[0]["params"]["ip"]
        with self._lock:
            self.calls.append(ip)
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            time.sleep(self._delay_for(ip))
            if self._retryable_for(ip):
                raise rewards.RetryableRoundError(f"pool busy for {ip}")
            return {
                "success": True,
                "feedback": {
                    "rs_exe": 1.0,
                    "rs_attack": self._attack_for(ip),
                    "rs_service": 1,
                },
            }
        finally:
            with self._lock:
                self.in_flight -= 1


@pytest.fixture()
def fake_soc(monkeypatch):
    """Wire the reward seams to a ``FakeRound`` selected by each test."""
    state = {"round": None, "penalty": 0.0}

    monkeypatch.setattr(rewards, "_tool_registry", lambda: FakeToolManager())
    monkeypatch.setattr(rewards, "_parse_tool_calls", fake_parse)
    monkeypatch.setattr(rewards, "_strategy_executor", lambda: state["round"])
    monkeypatch.setattr(rewards, "_judge_over_defence", lambda alert, policy: state["penalty"])
    return state


def _completions(count: int) -> list:
    return [completion(f"192.0.2.{index + 1}") for index in range(count)]


# ---------------------------------------------------------------------------------------
# The batch really runs concurrently
# ---------------------------------------------------------------------------------------
def test_rounds_run_concurrently(fake_soc, monkeypatch):
    """Eight rounds at concurrency 4 take about two waves, not eight serial rounds."""
    monkeypatch.setenv(rewards.REWARD_CONCURRENCY_ENV, "4")
    fake_soc["round"] = FakeRound(lambda ip: ROUND_S)
    completions = _completions(8)

    started = time.monotonic()
    result = rewards.sa_cascade_reward(completions, ["alert"] * len(completions))
    elapsed = time.monotonic() - started

    assert len(result) == len(completions)
    serial = len(completions) * ROUND_S
    # Generous: two waves are ~0.4 s against ~1.6 s serial, so even a loaded machine
    # stays well under 70% of the serial wall clock.
    assert elapsed < 0.7 * serial, f"{elapsed:.2f}s concurrent vs {serial:.2f}s serial"


def test_results_stay_aligned_with_completions(fake_soc, monkeypatch):
    """Out-of-order finishes must not reorder the rewards (``executor.map`` order)."""
    monkeypatch.setenv(rewards.REWARD_CONCURRENCY_ENV, "8")
    count = 6

    def delay_for(ip):
        # Completion 0 is the slowest, completion 5 the fastest: the finishes are the
        # reverse of the submission order.
        return 0.3 - 0.04 * _index_of(ip)

    fake_soc["round"] = FakeRound(delay_for, attack_for=lambda ip: _index_of(ip) * 0.1)

    result = rewards.sa_cascade_reward(_completions(count), ["alert"] * count)

    # R = 1 (format) + 1 (exec) + (1 - rs_attack) - 0, with rs_attack = 0.1 * i.
    expected = [3.0 - 0.1 * index for index in range(count)]
    assert result == pytest.approx(expected)


# ---------------------------------------------------------------------------------------
# The concurrency cap is enforced
# ---------------------------------------------------------------------------------------
def test_at_most_two_rounds_are_in_flight(fake_soc, monkeypatch):
    monkeypatch.setenv(rewards.REWARD_CONCURRENCY_ENV, "2")
    fake = FakeRound(lambda ip: 0.1)
    fake_soc["round"] = fake

    rewards.sa_cascade_reward(_completions(6), ["alert"] * 6)

    assert fake.max_in_flight <= 2
    # Six sleeping rounds with two workers do overlap; if they did not, the cap below
    # would pass for the wrong reason.
    assert fake.max_in_flight == 2


def test_concurrency_is_capped_by_the_batch_size(monkeypatch):
    monkeypatch.setenv(rewards.REWARD_CONCURRENCY_ENV, "8")
    assert rewards._reward_concurrency(3) == 3
    assert rewards._reward_concurrency(0) == 1


# ---------------------------------------------------------------------------------------
# Invalid settings fall back to the documented default
# ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["abc", "0"])
def test_invalid_concurrency_falls_back_to_the_default(monkeypatch, caplog, value):
    monkeypatch.setenv(rewards.REWARD_CONCURRENCY_ENV, value)
    with caplog.at_level(logging.WARNING, logger=rewards.__name__):
        assert rewards._reward_concurrency(8) == rewards.DEFAULT_REWARD_CONCURRENCY == 4
    assert any(
        rewards.REWARD_CONCURRENCY_ENV in record.getMessage() for record in caplog.records
    ), "an ignored setting must be reported, not silently replaced"


def test_unset_concurrency_uses_the_default(monkeypatch):
    monkeypatch.delenv(rewards.REWARD_CONCURRENCY_ENV, raising=False)
    assert rewards._reward_concurrency(10) == rewards.DEFAULT_REWARD_CONCURRENCY == 4


# ---------------------------------------------------------------------------------------
# A retryable failure still neutralises the whole (now concurrent) batch
# ---------------------------------------------------------------------------------------
def test_one_retryable_round_neutralises_the_whole_batch(fake_soc, monkeypatch):
    monkeypatch.setenv(rewards.REWARD_CONCURRENCY_ENV, "4")
    count = 5
    fake = FakeRound(
        lambda ip: 0.05,
        retryable_for=lambda ip: _index_of(ip) == 2,
    )
    fake_soc["round"] = fake

    result = rewards.sa_cascade_reward(_completions(count), ["alert"] * count)

    assert result == [rewards.EXCLUDED_BATCH_REWARD] * count
    # Uniform, not merely zero: a per-completion constant would still rank one above the
    # other and produce a non-zero GRPO advantage.
    assert len(set(result)) == 1
