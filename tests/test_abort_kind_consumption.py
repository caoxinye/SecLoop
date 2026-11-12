# SPDX-License-Identifier: Apache-2.0
"""The consumer side of `abort_kind`: separate "the defence blocked me" from "we broke".

A fatal abort and a perfect block produce the same bytes: an attack that aborts at the
pre-flight health anchor (`requests: 0`, `error: "lab target unreachable ... ConnectTimeout"`)
with every stage rewritten to `false` would be accepted by the RTC as a **perfect defence**
(`rs_attack = 0.0`, `rs_service = 1` ⇒ `R_eva = 1.0`). The bytes are valid; only the
*provenance* is missing.

`abort_kind` supplies the provenance, and the rules under test are:

* ``target-unreachable`` ⇒ **counts as blocked** (INTERFACES §2.1), flagged
  ``attack_unreached = True``;
* every other kind ⇒ **no verdict**: the round is unmeasured and earns nothing;
* causation is *not* inferred from the kind. ``caused_by_defence`` stays ``None`` until the
  pre-attack control (`resolve_causation`) answers it.

No lab, no VM: the SSH seam is faked.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from battlefield.attacks.sqli_lab import _blank_extracted, _blank_stages, _build_result  # noqa: E402
from battlefield.soc.execution_pipeline import resolve_causation  # noqa: E402
from battlefield.soc.red_team_controller import (  # noqa: E402
    RedTeamController,
    parse_attack_result,
)
from battlefield.soc.vagrant_driver import SshResult  # noqa: E402


def result_line(*, abort_kind=None, error=None, stages=None, requests_sent=0) -> str:
    """A real ``[RESULT]`` line built by the real producer."""
    payload = _build_result(
        target_ip="192.168.57.200",
        port=80,
        mode="time",
        delay=1.0,
        stages=_blank_stages() if stages is None else stages,
        extracted=_blank_extracted(),
        oracle_errors=0,
        requests_sent=requests_sent,
        elapsed_s=1.0,
        error=error,
        abort_kind=abort_kind,
    )
    return "[RESULT] " + json.dumps(payload)


class FakeDriver:
    """Just enough driver for `run_attack`: hand back a prepared stdout."""

    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.commands: list[str] = []

    def ssh(self, vm, command, timeout_s=None) -> SshResult:
        self.commands.append(command)
        return SshResult(returncode=self.returncode, stdout=self.stdout)

    def ip(self, vm) -> str:  # pragma: no cover - only if run_attack asks
        return "192.168.57.199"


def controller(stdout: str) -> RedTeamController:
    return RedTeamController(driver=FakeDriver(stdout))


# ---------------------------------------------------------------------------------------
# 1. The parser surfaces the field (pure)
# ---------------------------------------------------------------------------------------
def test_the_parser_surfaces_abort_kind() -> None:
    parsed = parse_attack_result(result_line(abort_kind="target-unreachable", error="blocked"))
    assert parsed["abort_kind"] == "target-unreachable"
    assert parsed["error"] == "blocked"


def test_a_completed_run_parses_as_no_abort_kind() -> None:
    assert parse_attack_result(result_line())["abort_kind"] is None


def test_an_unknown_kind_is_downgraded_to_unclassified() -> None:
    """A producer must not be able to mint a kind the consumer will trust by accident."""
    assert parse_attack_result(result_line(abort_kind="definitely-blocked"))["abort_kind"] == (
        "unclassified"
    )


def test_the_payload_is_still_retained_verbatim() -> None:
    """Consumers that need `requests` / `oracle_errors` must not have to re-parse stdout."""
    parsed = parse_attack_result(result_line(abort_kind="dependency-missing", requests_sent=0))
    assert parsed["payload"]["requests"] == 0
    assert parsed["payload"]["abort_kind"] == "dependency-missing"


# ---------------------------------------------------------------------------------------
# 2. run_attack: the block / no-verdict split
# ---------------------------------------------------------------------------------------
def test_an_unreachable_target_counts_as_blocked() -> None:
    """The attack never ran IS "it was blocked" -- but flagged, not assumed."""
    result = controller(
        result_line(abort_kind="target-unreachable", error="lab target unreachable: ConnectTimeout")
    ).run_attack("sqli", "kali", target_ip="192.168.57.200")

    assert result["success"] is True, "a block is a usable measurement"
    assert result["abort_kind"] == "target-unreachable"
    assert result["attack_unreached"] is True
    # The stages stay exactly as reported -- never fabricated into a success, and never
    # rewritten into anything else either.
    assert [s["success"] for s in result["stages"]] == [False] * len(result["stages"])
    assert result["caused_by_defence"] is None, (
        "the RTC cannot know whether the defence caused it; only the pre-attack control can"
    )


def test_an_unconfirmed_oracle_earns_nothing() -> None:
    """The all-false list is identical to a block, so only the kind can refuse credit."""
    result = controller(
        result_line(abort_kind="oracle-unconfirmed", error="time-based oracle not confirmed")
    ).run_attack("sqli", "kali", target_ip="192.168.57.200")

    assert result["success"] is False, "no verdict on the defence may be reported"
    assert result.get("stages") in ([], None), "an unmeasured round must not carry a block"
    assert "oracle-unconfirmed" in str(result.get("error"))


@pytest.mark.parametrize(
    "kind", ["dependency-missing", "config-invalid", "unclassified"]
)
def test_every_other_kind_is_unmeasured(kind: str) -> None:
    result = controller(result_line(abort_kind=kind, error="harness problem")).run_attack(
        "sqli", "kali", target_ip="192.168.57.200"
    )
    assert result["success"] is False
    assert result.get("stages") in ([], None)
    assert kind in str(result.get("error"))


def test_a_completed_run_is_unaffected() -> None:
    result = controller(result_line()).run_attack("sqli", "kali", target_ip="192.168.57.200")
    assert result["success"] is True
    assert result["abort_kind"] is None
    assert result["attack_unreached"] is False
    assert result["caused_by_defence"] is None


def test_an_unproven_block_is_flagged_attack_unreached() -> None:
    """A health-anchor timeout with `requests: 0`, replayed.

    It is a legitimate block -- but it is labelled `attack_unreached=True` and
    `caused_by_defence=None`, so nothing downstream can present it as *proof* that the
    strategy blocked the attack.
    """
    round_line = result_line(
        abort_kind="target-unreachable",
        error="lab target unreachable at http://192.168.57.200/health: ConnectTimeout: ...",
        requests_sent=0,
    )
    result = controller(round_line).run_attack("sqli", "kali", target_ip="192.168.57.200")
    assert result["success"] is True
    assert result["attack_unreached"] is True
    assert result["caused_by_defence"] is None, "unproven until the pre-attack control answers it"


# ---------------------------------------------------------------------------------------
# 3. The pre-attack control decides causation
# ---------------------------------------------------------------------------------------
REACHED = {"success": True, "attack_unreached": False, "stages": [{"name": "x", "success": True}]}
UNREACHED = {"success": True, "attack_unreached": True, "stages": []}


def test_the_control_proves_the_defence_did_it() -> None:
    """The target was reachable before deployment and unreachable after: only one thing
    changed, so the strategy caused the block."""
    assert resolve_causation(post_unreached=True, pre_attack_sample=True, pre_result=REACHED) is True


def test_an_already_broken_lab_vetoes_the_credit() -> None:
    """The control could not reach the target either, so the defence is not the cause."""
    assert resolve_causation(post_unreached=True, pre_attack_sample=True, pre_result=UNREACHED) is False


def test_without_a_control_causation_stays_unproven() -> None:
    assert resolve_causation(post_unreached=True, pre_attack_sample=False, pre_result=None) is None
    assert resolve_causation(post_unreached=True, pre_attack_sample=True, pre_result=None) is None


def test_a_control_that_could_not_measure_does_not_answer_the_question() -> None:
    """If the control itself produced no usable result, it cannot license a claim either way."""
    broken = {"success": False, "error": "attack produced no [RESULT] line"}
    assert resolve_causation(post_unreached=True, pre_attack_sample=True, pre_result=broken) is None


def test_when_the_post_attack_reached_the_target_the_question_does_not_arise() -> None:
    assert resolve_causation(post_unreached=False, pre_attack_sample=True, pre_result=REACHED) is None
    assert resolve_causation(post_unreached=False, pre_attack_sample=False, pre_result=None) is None


def test_the_veto_and_the_proof_are_mutually_exclusive() -> None:
    """No input may claim both, and the values are strict booleans/None (never truthy junk)."""
    for post in (True, False):
        for sample in (True, False):
            for pre in (None, REACHED, UNREACHED, {"success": False}):
                value = resolve_causation(
                    post_unreached=post, pre_attack_sample=sample, pre_result=pre
                )
                assert value is True or value is False or value is None
