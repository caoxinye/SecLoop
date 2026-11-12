# SPDX-License-Identifier: Apache-2.0
"""Offline tests for the policy execution validator (paper Eqs. 10-13).

``battlefield/soc/policy_execution_validator.py`` owns the measurement half of the
project's most-repeated invariant ("the validator measures, the reward layer inverts").
A source-only inspection cannot see a malformed tool result being silently dropped --
which shrinks Eq. 10's denominator ``l`` and therefore *raises* ``rs_exe`` -- so the
arithmetic is exercised directly here.

The module is importable without ``python-vagrant``: ``vagrant_driver`` imports that
library lazily inside a function, so the SOC package imports fine on a machine that
has no lab at all.  Nothing here touches a VM, the network or Suricata.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from battlefield.soc.policy_execution_validator import (  # noqa: E402
    PolicyExecutionValidator,
    compute_rs_attack,
    compute_rs_exe,
    compute_rs_service,
    validate,
)


def tools(*successes: bool) -> list[dict]:
    return [
        {"tool": f"t{i}", "success": ok, "output": "", "error": None}
        for i, ok in enumerate(successes)
    ]


def attack(*successes: bool) -> dict:
    return {
        "attack_mode": "sqli",
        "target_ip": "192.168.57.200",
        "score": 0.0,
        "stages": [
            {"name": f"s{i}", "success": ok, "weight": 1.0 / len(successes)}
            for i, ok in enumerate(successes)
        ],
        "error": None,
    }


PROBE_UP = {"target_http": True, "attacker_reachable": True}


# ---------------------------------------------------------------------------------------
# Eq. 10 - rs_exe
# ---------------------------------------------------------------------------------------
def test_rs_exe_is_the_mean_over_tool_calls():
    assert compute_rs_exe(tools(True, True, False, False)) == pytest.approx(0.5)
    assert compute_rs_exe(tools(True, True, True, True)) == pytest.approx(1.0)
    assert compute_rs_exe(tools(False, False)) == pytest.approx(0.0)


def test_empty_strategy_scores_zero_not_one():
    """Eq. 10 is undefined with no tool calls; it must not read as a perfect run."""
    assert compute_rs_exe([]) == 0.0
    assert compute_rs_exe(None) == 0.0


def test_malformed_tool_result_is_a_failure_not_a_drop():
    """Dropping it would keep ``l`` at 3 and score 3/3 = 1.0, so the entry is counted
    as a failure.

    An entry that is not an object cannot be verified as a successful deployment, so
    counting it as a failure is the only direction that does not flatter the strategy.
    """
    assert compute_rs_exe(tools(True, True, True) + ["NOT-AN-OBJECT"]) == pytest.approx(0.75)
    # Eq. 10's result is rounded to 4 dp, so compare with a tolerance wider than that.
    assert compute_rs_exe(tools(True, True) + [None]) == pytest.approx(2 / 3, abs=1e-4)


def test_malformed_tool_result_does_not_crash_the_public_function():
    """``compute_rs_exe`` must survive a non-object entry instead of raising
    ``AttributeError`` on ``r.get``."""
    assert compute_rs_exe([{"tool": "a", "success": True}, 42]) == pytest.approx(0.5)


def test_raw_and_already_normalised_input_agree():
    """``validate`` normalises and then calls this, so the two paths must be identical."""
    from battlefield.soc.policy_execution_validator import _normalize_tools

    raw = [{"tool": "a", "success": True}, {"tool": "b", "success": False}, "junk"]
    assert compute_rs_exe(raw) == compute_rs_exe(_normalize_tools(raw))


def test_non_list_container_is_not_iterated_as_tools():
    """A bare string is the classic wrong input; it must not become per-character tools."""
    assert compute_rs_exe("block_ip") == 0.0


# ---------------------------------------------------------------------------------------
# Eq. 11 - rs_attack is the raw measurement
# ---------------------------------------------------------------------------------------
def test_rs_attack_is_the_raw_success_rate():
    assert compute_rs_attack(attack(True, True, False, False, False)["stages"]) == pytest.approx(0.4)


def test_rs_attack_is_never_inverted():
    """A fully successful attack scores 1.0, NOT 0.0 - the inversion belongs to the reward."""
    assert compute_rs_attack(attack(True, True)["stages"]) == pytest.approx(1.0)
    assert compute_rs_attack(attack(False, False)["stages"]) == pytest.approx(0.0)


def test_empty_stage_list_is_zero_not_a_perfect_defence():
    """An attack that never ran must not score `1.0` (that is full defence)."""
    assert compute_rs_attack([]) == 0.0
    assert compute_rs_attack(None) == 0.0


def test_rs_attack_ignores_stage_weights():
    """Eq. 11 is an unweighted mean; the weights belong to the probe's own `score`."""
    stages = [
        {"name": "a", "success": True, "weight": 0.1},
        {"name": "b", "success": True, "weight": 0.1},
        {"name": "c", "success": False, "weight": 0.4},
        {"name": "d", "success": False, "weight": 0.4},
    ]
    # unweighted: 2/4 = 0.5.  A weighted sum would have given 0.2.
    assert compute_rs_attack(stages) == pytest.approx(0.5)


# ---------------------------------------------------------------------------------------
# A malformed stage must not shrink the Eq. 11 denominator
# ---------------------------------------------------------------------------------------
def test_a_malformed_stage_counts_as_failed_and_keeps_the_denominator():
    """Skipping a malformed stage shrinks ``m``, and the mean then moves the flattering way.

    Four readable stages where one succeeded gives 0.25. Dropping a fifth, unreadable entry
    would give 0.25 over four stages -- i.e. the anomaly silently *raises* ``rs_attack`` if
    the dropped entry would have failed. The validator already refuses this for malformed
    *tool* results, so the stage path must match.
    """
    stages = [
        {"name": "a", "success": True},
        {"name": "b", "success": False},
        {"name": "c", "success": False},
        {"name": "d", "success": False},
        "not-an-object",  # must be counted, not dropped
    ]
    assert compute_rs_attack(stages) == pytest.approx(1 / 5)


def test_a_malformed_stage_cannot_be_read_as_a_success():
    """The placeholder is a failure, never a free point."""
    assert compute_rs_attack(["junk", "junk"]) == pytest.approx(0.0)


def test_the_normaliser_keeps_the_reported_length():
    from battlefield.soc.policy_execution_validator import _normalize_stages

    raw = [{"name": "a", "success": True}, None, 42, {"success": False}]
    normalized = _normalize_stages(raw, field="attack_result.stages")
    assert len(normalized) == len(raw), "the denominator must follow the reported stage count"
    assert all(isinstance(item["success"], bool) for item in normalized)
    assert normalized[1]["success"] is False and normalized[2]["success"] is False


# ---------------------------------------------------------------------------------------
# Eq. 12 - rs_service is strict {0, 1} and never inferred
# ---------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("probe", "expected"),
    [
        ({"target_http": True, "attacker_reachable": True}, 1),
        ({"target_http": True, "attacker_reachable": False}, 0),
        ({"target_http": False, "attacker_reachable": True}, 0),
        ({"target_http": False, "attacker_reachable": False}, 0),
        ({}, 0),
        (None, 0),
    ],
)
def test_rs_service_requires_both_real_probes(probe, expected):
    assert compute_rs_service(probe) == expected


def test_rs_service_is_strictly_binary():
    for probe in (PROBE_UP, {}, {"target_http": "yes", "attacker_reachable": "no"}):
        assert compute_rs_service(probe) in (0, 1)


# ---------------------------------------------------------------------------------------
# Eq. 13 - F_i, and the whole vector
# ---------------------------------------------------------------------------------------
def test_f_i_is_the_sum_of_the_three_measurements():
    feedback = validate(tools(True, True), attack(True, False), PROBE_UP)
    assert feedback["rs_exe"] == pytest.approx(1.0)
    assert feedback["rs_attack"] == pytest.approx(0.5)
    assert feedback["rs_service"] == 1
    assert feedback["F_i"] == pytest.approx(2.5)


def test_validate_reports_the_raw_attack_value_not_the_defence():
    """The reward layer owns `1 - rs_attack`; this layer must not do it twice."""
    feedback = validate(tools(True), attack(True), PROBE_UP)
    assert feedback["rs_attack"] == pytest.approx(1.0)


def test_the_facade_matches_the_pure_functions():
    """`PolicyExecutionValidator` delegates; the two entry points must agree."""
    validator = PolicyExecutionValidator()
    direct = validate(tools(True, False), attack(True, True), PROBE_UP)
    through_object = validator.validate(tools(True, False), attack(True, True), PROBE_UP)
    assert direct == through_object
    assert validator.compute_rs_exe(tools(True, False)) == pytest.approx(0.5)
    assert validator.compute_rs_attack(attack(True, True)["stages"]) == pytest.approx(1.0)
