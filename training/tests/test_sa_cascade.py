# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the SA-GRPO four-stage cascade reward.

Two of the external boundaries - the SOC transport and the LLM penalty judge - are
replaced through the module-level seams of :mod:`open_r1.rewards`, so most of these
tests need neither a running SOC server nor a configured LLM endpoint.  Everything
under test is real: the format-stage validation, the cascade arithmetic, the
clipping, the single-request strategy submission and the polarity rule.

Two tests go further and use the **real** shared implementations
(``agent.llm.llm_interface.extract_tool_calls`` and
``agent.tools.security_tools.create_security_tools``), which is the integration
point ``INTERFACES.md`` §6/§8 is about.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

TRAINING_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRAINING_ROOT / "src"))

from open_r1 import rewards  # noqa: E402  (import after sys.path setup)

try:  # the SOC client needs `requests`; these tests skip themselves without it
    from agent.tools.batch_executor import SOCBusyError, SOCUnavailableError  # noqa: E402
except ImportError:  # pragma: no cover - depends on the test machine
    SOCBusyError = SOCUnavailableError = None  # type: ignore[assignment]

VALID_STRATEGY = json.dumps([{"tool": "block_ip", "params": {"ip": "192.168.57.199"}}])
THREE_TOOL_STRATEGY = json.dumps(
    [
        {"tool": "block_ip", "params": {"ip": "192.168.57.199"}},
        {"tool": "bash", "params": {"command": "echo hardened"}},
        {"tool": "powershell", "params": {"command": "Get-Service"}},
    ]
)
UNAVAILABLE_CONFIG = Path(__file__).resolve().parent / "fixtures" / "agent_config_no_endpoint.json"


class JudgeUnavailable(RuntimeError):
    """Stand-in for the llm_judge.PenaltyJudgeUnavailableError."""


class RegistryRejection(ValueError):
    """Stand-in for agent.tools.tool_manager.StrategyValidationError (a ValueError)."""


def completion(text: str) -> list:
    """A TRL-shaped completion payload."""
    return [{"role": "assistant", "content": text}]


class FakeToolManager:
    """Minimal stand-in for the agent's authoritative ToolManager."""

    def get_available_tools(self) -> list:
        return ["block_ip", "bash", "powershell"]


def fake_parse(text: str):
    """Mirror of the shared parser: always emits a ``params`` object."""
    candidate = text
    if "```" in text:
        start = text.find("```")
        body = text.find("\n", start)
        end = text.find("```", body)
        if body != -1 and end != -1:
            candidate = text[body:end].strip()
    parsed = json.loads(candidate)  # raises ValueError for garbage, like StrategyParseError
    if isinstance(parsed, dict) and "tool" in parsed:
        parsed = [parsed]
    if not isinstance(parsed, list) or not parsed:
        raise ValueError("empty tool-call strategy")
    return [{"tool": item.get("tool"), "params": item.get("params") or {}} for item in parsed]


@pytest.fixture()
def env(monkeypatch):
    """Wire the reward seams and expose their mutable state to the tests."""
    state = {
        "feedback": {"rs_exe": 1.0, "rs_attack": 0.0, "rs_service": 1},
        "success": True,
        "penalty": 0.0,
        "judge_error": None,
        "registry_error": None,
        "busy_error": None,
        "strategy_calls": [],
        "judge_calls": [],
    }

    monkeypatch.setattr(rewards, "_tool_registry", lambda: FakeToolManager())
    monkeypatch.setattr(rewards, "_parse_tool_calls", fake_parse)

    def make_executor():
        class Executor:
            def execute_strategy(self, strategy, *args, **kwargs):
                state["strategy_calls"].append(list(strategy))
                if state["busy_error"] is not None:
                    raise state["busy_error"]
                if state["registry_error"] is not None:
                    raise state["registry_error"]
                if not state["success"]:
                    return {"success": False, "error": "stub failure"}
                return {"success": True, "feedback": dict(state["feedback"])}

        return Executor()

    monkeypatch.setattr(rewards, "_strategy_executor", make_executor)

    def judge(alert, policy):
        if state["judge_error"] is not None:
            raise state["judge_error"]
        state["judge_calls"].append((alert, policy))
        return state["penalty"]

    monkeypatch.setattr(rewards, "_judge_over_defence", judge)
    return state


# ---------------------------------------------------------------------------------------
# Stage 1 - format reward (Eq. 18)
# ---------------------------------------------------------------------------------------
def test_format_stage_accepts_valid_json(env):
    env["feedback"] = {"rs_exe": 1.0, "rs_attack": 0.25, "rs_service": 1}
    result = rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["alert-text"])
    # 1 (format) + 1 (exec) + (1 - 0.25) (evaluation) - 0 (penalty) = 2.75
    assert result == [pytest.approx(2.75)]
    assert len(env["strategy_calls"]) == 1


def test_format_stage_accepts_fenced_json(env):
    fenced = f"here is the plan\n```json\n{VALID_STRATEGY}\n```\ndone"
    result = rewards.sa_cascade_reward([completion(fenced)], ["alert-text"])
    assert result == [pytest.approx(3.0)]


def test_format_stage_rejects_invalid_json(env):
    result = rewards.sa_cascade_reward([completion("not json at all")], ["alert-text"])
    assert result == [0.0]
    assert env["strategy_calls"] == []
    assert env["judge_calls"] == []


def test_format_stage_rejects_unknown_tool(env):
    payload = json.dumps([{"tool": "rm_rf", "params": {}}])
    assert rewards.sa_cascade_reward([completion(payload)], ["alert-text"]) == [0.0]
    assert env["strategy_calls"] == []


def test_format_stage_rejects_non_object_params(env):
    payload = json.dumps([{"tool": "bash", "params": "echo hi"}])
    assert rewards.sa_cascade_reward([completion(payload)], ["alert-text"]) == [0.0]


def test_format_stage_rejects_bare_non_object_payload(env):
    assert rewards.sa_cascade_reward([completion('"just a string"')], ["alert-text"]) == [0.0]


def test_validate_tool_strategy_requires_a_params_object(monkeypatch):
    """Defence in depth: the shape check holds even if a parser omits ``params``."""
    monkeypatch.setattr(rewards, "_parse_tool_calls", lambda text: [{"tool": "bash"}])
    assert rewards.validate_tool_strategy("x", FakeToolManager()) is None


def test_validate_tool_strategy_returns_normalised_strategy(env):
    strategy = rewards.validate_tool_strategy(VALID_STRATEGY, FakeToolManager())
    assert strategy == [{"tool": "block_ip", "params": {"ip": "192.168.57.199"}}]
    assert rewards.validate_tool_strategy("nonsense", FakeToolManager()) is None


# ---------------------------------------------------------------------------------------
# Stages 2 and 3 - execution gate (Eq. 19) and evaluation polarity (Eq. 20)
# ---------------------------------------------------------------------------------------
def test_execution_gate_is_binary(env):
    env["feedback"] = {"rs_exe": 0.5, "rs_attack": 0.0, "rs_service": 1}
    # format 1 + exec 0 + evaluation (1 - 0) - 0 = 2.0
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(2.0)]


def test_evaluation_reward_inverts_raw_attack_measurement(env):
    """R_eva = 1 - rs_attack; a fully successful attack is not rewarded.

    `1 - rs_attack` is this repository's estimator of Eq. 20's `W_BATTLE-FIELD`
    ("absence of alarms") -- the paper states the semantics, not the formula.
    """
    env["feedback"] = {"rs_exe": 1.0, "rs_attack": 1.0, "rs_service": 1}
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(2.0)]

    env["feedback"] = {"rs_exe": 1.0, "rs_attack": 0.0, "rs_service": 1}
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(3.0)]

    env["feedback"] = {"rs_exe": 1.0, "rs_attack": 0.4, "rs_service": 1}
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(2.6)]


# ---------------------------------------------------------------------------------------
# Stage 3 follows Eq. 20's semantics -- `rs_service` does NOT gate it.
# The estimator `1 - rs_attack` is this repository's; the paper gives the term, not a formula.
# ---------------------------------------------------------------------------------------
def test_blocking_the_attack_earns_the_point_whatever_the_service_did(env):
    """Eq.20 is ``R_eva(o_i) = W_BATTLE-FIELD(o_i)`` -- the absence of alarms.

    Stage 3 deliberately does **not** multiply by ``rs_service``: doing so would read
    §IV-D's "and does not cause any disruption" into Eq.20 and make the evaluation
    reward conditional on our own service probe.  The paper's semantics are what is
    implemented, so a perfect block earns the point even if the service went down.

    What still bounds over-defence: the Eq.21 penalty judge, ``rs_service`` still entering
    ``F_i`` (Eq.13), and ``R_exec`` still requiring a deployable strategy.  If §IV-D's
    conjunction is ever wanted back, change ``rewards.py`` *and* INTERFACES §10.2.
    """
    env["feedback"] = {"rs_exe": 1.0, "rs_attack": 0.0, "rs_service": 0}
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(3.0)]


def test_the_service_flag_changes_nothing_in_the_total(env):
    for service in (0, 1):
        env["feedback"] = {"rs_exe": 1.0, "rs_attack": 0.4, "rs_service": service}
        assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(2.6)]


def test_missing_rs_service_is_still_unmeasured(env):
    """Dropping the multiplication must not turn a missing field into a flattering number.

    This is not a gate on Eq.20 -- it is the "no feedback vector arrived" rule: the SOC's
    vector is only a measurement if it carries its components.
    """
    env["feedback"] = {"rs_exe": 1.0, "rs_attack": 0.0}  # rs_service omitted
    env["penalty"] = 0.25
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(0.75)]


@pytest.mark.parametrize("value", [2, -1, 0.5, "maybe", {}, []])
def test_non_binary_rs_service_is_read_strictly(value):
    """Eq. 12 is strict ``{0, 1}``; a non-binary flag is never read as "healthy service".

    It does not withdraw ``R_eva``, so the assertion is on the parsed flag -- which
    is what still feeds ``F_i`` (Eq. 13) and the logs.
    """
    assert rewards._service_flag(value) == 0


@pytest.mark.parametrize("value", [1, True, 1.0, "1", "true", "yes"])
def test_affirmative_rs_service_spellings_are_accepted(value):
    assert rewards._service_flag(value) == 1


def test_the_cascade_stays_within_range(env):
    """R = R_format + R_exec + R_eva - P is clipped to [0, 3] (INTERFACES §10.2)."""
    for service in (0, 1):
        for attack in (0.0, 0.5, 1.0):
            env["feedback"] = {"rs_exe": 1.0, "rs_attack": attack, "rs_service": service}
            total = rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"])[0]
            assert 0.0 <= total <= rewards.MAX_CASCADE_REWARD
            assert rewards.MAX_CASCADE_REWARD == 3.0


def test_missing_rs_attack_is_unmeasured_not_a_perfect_defence(env):
    """A missing measurement must not be defaulted to R_eva = 1.0 (INTERFACES §4.2)."""
    env["feedback"] = {"rs_exe": 1.0}  # rs_attack omitted by the SOC
    env["penalty"] = 0.25
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(0.75)]


def test_failed_round_trip_zeroes_exec_and_evaluation_but_keeps_format(env):
    env["success"] = False
    env["penalty"] = 0.25
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(0.75)]


# ---------------------------------------------------------------------------------------
# Capacity exhaustion (HTTP 429) is excluded, not scored (INTERFACES §3.1)
# ---------------------------------------------------------------------------------------
def test_a_busy_pool_excludes_the_batch_instead_of_scoring_it(env, monkeypatch):
    """A busy VM pool is our problem, not the policy's.

    ``INTERFACES.md`` §3.1 requires ``429`` (retryable) to be told apart from
    ``200 + success:false`` (the strategy failed).  Scoring the retryable one ``0.0``
    would teach the policy that a good strategy failed, so the batch is neutralised:
    every completion gets the *same* reward, which in GRPO means zero advantage and
    therefore no gradient.
    """
    monkeypatch.delenv("SECLOOP_RETRYABLE_POLICY", raising=False)
    pytest.importorskip("requests")
    env["busy_error"] = SOCBusyError("SOC endpoint returned HTTP 429 (capacity exhausted)")
    result = rewards.sa_cascade_reward(
        [completion(VALID_STRATEGY), completion(VALID_STRATEGY)], ["a", "a"]
    )
    assert result == [
        pytest.approx(rewards.EXCLUDED_BATCH_REWARD),
        pytest.approx(rewards.EXCLUDED_BATCH_REWARD),
    ]
    # Uniform, not merely zero: a per-completion constant would still rank one above the
    # other and produce a non-zero advantage.
    assert len(set(result)) == 1


def test_the_exclusion_can_be_turned_back_into_a_zero_score(env, monkeypatch):
    """``SECLOOP_RETRYABLE_POLICY=zero`` scores the round instead of excluding it."""
    monkeypatch.setenv("SECLOOP_RETRYABLE_POLICY", "zero")
    pytest.importorskip("requests")
    env["busy_error"] = SOCBusyError("429")
    env["penalty"] = 0.25
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(0.75)]


def test_a_non_retryable_transport_failure_is_still_scored(env):
    """Only capacity exhaustion is excluded; a genuine transport error stays a 0."""
    pytest.importorskip("requests")
    env["busy_error"] = SOCUnavailableError("connection refused")
    env["penalty"] = 0.25
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(0.75)]


def test_strategy_rejected_by_the_registry_earns_only_the_format_reward(env):
    """A strategy naming a tool the registry rejects is never executed.

    The round comes back `success: false` with `rs_exe = rs_attack = rs_service = 0`,
    so the cascade returns the format reward alone: `1.0 + 0 + 0 - 0`.

    The consequence is worth stating because it is deliberate: a *rejected* strategy
    therefore scores **higher** than a strategy that ran and failed with a penalty
    (0.75, in the failed-round-trip test above).  The format reward measures whether
    the model emitted a parsable call; whether the call was useful is exactly what the
    execution and evaluation terms are for.
    """
    env["registry_error"] = RegistryRejection("legacy parameter 'ip_address' is not valid for block_ip")
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(1.0)]


# ---------------------------------------------------------------------------------------
# Stage 4 - penalty (Eq. 21)
# ---------------------------------------------------------------------------------------
def test_penalty_is_subtracted(env):
    env["feedback"] = {"rs_exe": 1.0, "rs_attack": 0.0, "rs_service": 1}
    env["penalty"] = 0.5
    assert rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"]) == [pytest.approx(2.5)]


def test_penalty_runs_only_after_the_format_gate(env):
    rewards.sa_cascade_reward([completion("{}")], ["a"])
    assert env["judge_calls"] == []

    rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["alert-body"])
    assert len(env["judge_calls"]) == 1
    alert_seen, policy_seen = env["judge_calls"][0]
    assert alert_seen == "alert-body"
    assert json.loads(policy_seen) == [{"tool": "block_ip", "params": {"ip": "192.168.57.199"}}]


def test_unconfigured_judge_is_not_silently_swallowed(env):
    env["judge_error"] = JudgeUnavailable("no endpoint configured")
    with pytest.raises(JudgeUnavailable):
        rewards.sa_cascade_reward([completion(VALID_STRATEGY)], ["a"])


def test_judge_raises_when_the_shared_endpoint_is_blank(monkeypatch):
    """End-to-end: a blank endpoint surfaces as PenaltyJudgeUnavailableError, never 0.0."""
    pytest.importorskip("requests")
    from open_r1.utils.llm_judge import PenaltyJudgeUnavailableError, judge_over_defence

    monkeypatch.setenv("SECLOOP_AGENT_CONFIG", str(UNAVAILABLE_CONFIG))
    with pytest.raises(PenaltyJudgeUnavailableError):
        judge_over_defence("alert", "[]")


# ---------------------------------------------------------------------------------------
# Formula, clipping and the single-round-trip requirement
# ---------------------------------------------------------------------------------------
def test_cascade_total_formula_and_clipping():
    assert rewards.cascade_total(1.0, 1.0, 1.0, 0.0) == pytest.approx(3.0)
    assert rewards.cascade_total(1.0, 1.0, 1.0, 1.0) == pytest.approx(2.0)
    assert rewards.cascade_total(1.0, 0.0, 0.0, 0.5) == pytest.approx(0.5)
    assert rewards.cascade_total(1.0, 1.0, 1.0, 5.0) == 0.0
    assert rewards.cascade_total(1.0, 1.0, 1.0, -1.0) == rewards.MAX_CASCADE_REWARD


def test_whole_strategy_is_submitted_in_one_request(env):
    """The per-tool fan-out is forbidden (INTERFACES.md §5)."""
    result = rewards.sa_cascade_reward([completion(THREE_TOOL_STRATEGY)], ["a"])
    assert result == [pytest.approx(3.0)]
    assert len(env["strategy_calls"]) == 1
    assert len(env["strategy_calls"][0]) == 3


def test_batch_is_scored_elementwise(env):
    env["feedback"] = {"rs_exe": 1.0, "rs_attack": 0.5, "rs_service": 1}
    result = rewards.sa_cascade_reward(
        [completion(VALID_STRATEGY), completion("broken"), completion(VALID_STRATEGY)],
        ["a1", "a2", "a3"],
    )
    assert result == [pytest.approx(2.5), 0.0, pytest.approx(2.5)]
    assert len(env["strategy_calls"]) == 2


# ---------------------------------------------------------------------------------------
# Integration with the real shared implementations
# ---------------------------------------------------------------------------------------
def test_real_parser_and_registry_drive_the_format_stage(monkeypatch):
    """No stubs: the agent's parser and the agent's tool registry decide stage 1."""
    pytest.importorskip("requests")
    from open_r1.utils.security_tools import TOOL_NAMES, create_security_tools

    manager = create_security_tools()
    # Two different sets, and the difference is the point (INTERFACES §6, paper Eq. 3):
    # `TOOL_NAMES` is the full catalogue -- membership checks must not depend on the
    # host -- while a manager registers only what *this environment* can actually run.
    # With no probe the registry cannot know the environment, so it deliberately registers
    # the whole catalogue for membership and warns: `powershell` is then catalogued but
    # **not executed** (the SOC renders with `bash -lc` and raises for it). The
    # discovery path is asserted in tests/lab/test_capability_probe.py. A
    # platform-filtered manager would instead pin the behaviour that lets the model emit
    # a Windows-only tool next to `Platform: Linux`.
    assert list(manager.get_available_tools()) == ["block_ip", "bash", "powershell"]
    assert list(TOOL_NAMES) == ["block_ip", "bash", "powershell"]

    # What a probed environment registers is what the probe found (paper Eq. 3).
    probed = create_security_tools(available=["block_ip", "bash"])
    assert list(probed.get_available_tools()) == ["block_ip", "bash"]
    assert probed.get_tool("powershell") is None

    assert rewards.validate_tool_strategy(VALID_STRATEGY, manager) == [
        {"tool": "block_ip", "params": {"ip": "192.168.57.199"}}
    ]
    assert rewards.validate_tool_strategy("no json here", manager) is None
    assert rewards.validate_tool_strategy("[]", manager) is None
    assert rewards.validate_tool_strategy(json.dumps([{"tool": "nope", "params": {}}]), manager) is None
    # The shared parser tolerates prose and fences around the JSON payload.
    assert rewards.validate_tool_strategy(f"plan:\n```json\n{VALID_STRATEGY}\n```\n", manager) is not None

    # "Names a real tool" and "this environment can run it" are two different checks, and
    # the boundary is the probed tool set (paper Eq. 3):
    assert rewards.validate_tool_strategy(THREE_TOOL_STRATEGY, manager) is not None, (
        "without a probe the registry only knows membership, and every name in the "
        "three-tool fixture is catalogued"
    )
    assert rewards.validate_tool_strategy(THREE_TOOL_STRATEGY, probed) is None, (
        "a strategy naming a tool this environment cannot run must be rejected before "
        "execution; advertising it in T_A is what produced such strategies in the first place"
    )


# ---------------------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------------------
class ScriptArgs:
    def __init__(self, reward_funcs):
        self.reward_funcs = reward_funcs


def test_registry_maps_sa_cascade():
    funcs = rewards.get_reward_funcs(ScriptArgs(["sa_cascade"]))
    assert funcs == [rewards.sa_cascade_reward]


def test_registry_rejects_superseded_names():
    for stale in ("ability", "ability_format", "ability_quick", "ability_judge"):
        with pytest.raises(ValueError):
            rewards.get_reward_funcs(ScriptArgs([stale]))


# ---------------------------------------------------------------------------------------
# S_r authority (INTERFACES.md §9)
# ---------------------------------------------------------------------------------------
def test_summarizer_delegates_to_the_ids_authority():
    """``C`` must be rendered by the one authority on both the training and eval paths."""
    from ids.combine_ids_log import summarize_fastlog as ids_summarize_fastlog
    from ids.combine_ids_log import summarize_lines as ids_summarize_lines

    from open_r1.utils import summarizer as training_summarizer

    assert training_summarizer.summarize_lines is ids_summarize_lines
    assert training_summarizer.summarize_fastlog is ids_summarize_fastlog
    assert training_summarizer.DEFAULT_WINDOW_S == ids_summarize_lines.__defaults__[0]

    summariser = training_summarizer.Summarizer()
    assert summariser.summarize_to_str("") == ""
    assert summariser.summarize_to_str("   \n\t\n ") == ""
    assert training_summarizer.split_fastlog_lines("") == []

    # Legacy pre-aggregated digest lines are NOT accepted by the canonical path, so a
    # corpus in that grammar is dropped loudly instead of being summarised by two
    # different grammars.  Structural parser fixture (RFC 5737 documentation IPs); it is
    # not an alert source and never reaches the prompt.
    digest = (
        "Time range: 2024-01-01 00:00:00 to 2024-01-01 00:05:00, "
        "detected 3 times 'SQL Injection Attempt' attack, "
        "source IP: 192.0.2.10, target: 192.0.2.20, risk level: 2"
    )
    assert summariser.summarize_to_str(digest) == ""
    assert training_summarizer.parse_legacy_digest("") == ""
    assert training_summarizer.parse_legacy_digest(digest).startswith("[SQL Injection Attempt] source=192.0.2.10")


# ---------------------------------------------------------------------------------------
# Recipe contract (INTERFACES.md §10.1)
# ---------------------------------------------------------------------------------------
def test_recipe_declares_every_sa_grpo_value():
    recipe = (TRAINING_ROOT / "recipes" / "Qwen2.5-7B-Instruct" / "grpo" / "config.yaml").read_text(
        encoding="utf-8"
    )
    for line in (
        "num_generations: 7",
        "scale_rewards: false",
        "beta: 0.0",
        "epsilon: 0.2",
        "epsilon_high: 0.28",
        "loss_type: dr_grpo",
        "learning_rate: 3.0e-06",
        "num_train_epochs: 1",
        "per_device_train_batch_size: 4",
        "gradient_accumulation_steps: 1",
        "torch_dtype: bfloat16",
        "model_name_or_path: Qwen/Qwen2.5-7B-Instruct",
    ):
        assert line in recipe, f"recipe is missing {line!r}"
    assert "sa_cascade" in recipe


# ---------------------------------------------------------------------------------------
# The documented GRPO-baseline escape hatch has to be reachable from the CLI
# ---------------------------------------------------------------------------------------
def test_the_grpo_baseline_escape_hatch_reaches_the_cli():
    """``validate_sa_grpo_config(strict=False)`` is documented as "useful when a
    deliberate GRPO baseline is being run", but its only call site passed the default
    ``strict=True`` and no CLI or config switch could change that, so a baseline run
    could not get past the SA-GRPO gate at all.

    Checked at source level on purpose: ``sa_grpo_trainer`` imports TRL, which the
    offline test environment does not install.
    """
    configs = (TRAINING_ROOT / "src" / "open_r1" / "configs.py").read_text(encoding="utf-8")
    grpo = (TRAINING_ROOT / "src" / "open_r1" / "grpo.py").read_text(encoding="utf-8")

    assert "allow_non_sa_grpo" in configs, (
        "GRPOConfig does not declare allow_non_sa_grpo, so the escape hatch cannot be "
        "reached from the command line"
    )
    assert re.search(r"validate_sa_grpo_config\(\s*training_args\s*,\s*strict=", grpo), (
        "grpo.py calls validate_sa_grpo_config without deriving `strict` from the flag"
    )
    assert "allow_non_sa_grpo" in grpo
