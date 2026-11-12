# SPDX-License-Identifier: Apache-2.0
"""Four-stage cascade reward for SA-GRPO - the paper's Section III-B in code.

Pipeline (``INTERFACES.md`` §10.2), evaluated independently for every completion:

===== ============ ======== ==========================================================
stage name         paper    rule
===== ============ ======== ==========================================================
1     ``R_format`` Eq. 18  JSON parses **and** every tool name is in the registry;
                            failing here scores exactly ``0.0``
2     ``R_exec``   Eq. 19  ``R_exec = 1.0`` iff ``rs_exe == 1.0`` (0/1 gate)
3     ``R_eva``    Eq. 20  ``R_eva = 1 - rs_attack`` (no ``rs_service`` gate)
4     ``P``        Eq. 21  LLM-judge over-defence level, **subtracted**
===== ============ ======== ==========================================================

``R = R_format + R_exec + R_eva - P`` clipped to ``[0, 3]``.

Stage 3: Eq. 20's absence-of-alarms reward
-----------------------------------------
Eq. 20 is ``R_eva(o_i) = W_BATTLE-FIELD(o_i) ∈ [0, 1]``, and the paper says a score of 1
"indicates the absence of warning alarms".  **If the attack is blocked, the strategy earns
the point**, with no further condition.

The value is computed as ``1 - rs_attack``: ``W_BATTLE-FIELD`` is defined in the paper only
as "a function based on BATTLE-FIELD that evaluates the defensive and mitigation
capabilities", and the complement of the measured attack success is that function.

``rs_service`` is deliberately not a factor.  Making Eq. 20 conditional on Eq. 12 -- which
§IV-D (a *correct* strategy "effectively defends ... and does not cause any disruption")
and §II-C-3 (service availability feeds the evaluation reward) would suggest -- gates the
evaluation reward on a probe of our own, so a dropped probe withdraws the point even from a
strategy that genuinely blocked the attack.
The reasoning is sound but it is a **deviation**, and it has a cost in the other
direction too: a defence blocked by a *harness* failure would have been gated out only
because the service probe happened to fail.

Consequence, stated rather than hidden: a strategy that blocks the attack by taking the
blue-team service down also earns ``R_eva = 1.0``.  Nothing inside this module
counterbalances that -- the total is ``R_format + R_exec + R_eva - P``, so ``F_i`` (Eq. 13)
and its ``rs_service`` component are measured, logged and never scored:

* ``rs_service`` is still a reported component of the feedback vector and still enters
  ``F_i`` (Eq. 13) -- it is measured, logged, and never inverted, but **it changes no
  reward**;
* ``R_exec`` (Eq. 19) still requires the whole strategy to have been deployable;
* the Eq. 21 penalty judge is the only reward-side place over-defence is caught, and it
  needs a configured LLM endpoint (it raises rather than returning ``0.0``).

If §IV-D's conjunction ever needs to gate stage 3 again, change it here **and** in
``docs/INTERFACES.md`` §10.2, because that document is the frozen contract.

Polarity (``INTERFACES.md`` §4 - read this before editing)
----------------------------------------------------------
The policy execution validator reports ``rs_attack`` as the **raw Eq. 11
measurement**: the fraction of attack stages that succeeded, so ``1.0`` means the
attack fully succeeded (i.e. the defence failed).  The validator must never
invert it, and neither may this module invert it twice.  ``1 - rs_attack`` is
computed in exactly one place: :func:`sa_cascade_reward`, stage 3.  The SOC also
exposes ``feedback["defense_effectiveness"]`` as a read-only convenience copy of
``1 - rs_attack``; it is **not** used here, precisely so the inversion cannot
happen twice.

Failure policy
--------------
The penalty stage must not silently degrade.  :func:`judge_over_defence` raises
when no LLM endpoint is configured (``INTERFACES.md`` §7.1) and raises when the
judge response is unusable, instead of substituting ``0.0``.

The measurement stages follow the same principle in the other direction: a round
whose ``rs_exe``/``rs_attack`` never arrived is **unmeasured**, so ``R_exec`` and
``R_eva`` are ``0.0`` rather than being defaulted to a flattering value.  In
particular, a missing ``rs_attack`` must never become ``R_eva = 1.0``.

**Except when the failure is ours, not the policy's.**  A VM pool at capacity is a
retryable transport failure, and scoring it ``0.0`` teaches the policy that a
perfectly good strategy failed (``INTERFACES.md`` §3.1 distinguishes ``429`` from
``200 + success:false`` for exactly this reason).  Such a round is **excluded from the
sample** instead: see :class:`RetryableRoundError` and ``SECLOOP_RETRYABLE_POLICY``.
An excluded sample contributes no gradient; it is not a zero.

Dataset requirement
-------------------
Both the trainer and this module expect one text column, ``alerts``, holding the
raw IDS alert digest for the prompt (see ``INTERFACES.md`` §9/§11).  It is the IDS
column the summarizer compresses into ``C``.

Concurrency
-----------
Every completion is one SOC round, and a round costs minutes, so the batch is scored on
a :class:`~concurrent.futures.ThreadPoolExecutor`.  ``SECLOOP_REWARD_CONCURRENCY``
(default 4) caps how many rounds are in flight, and ``ThreadPoolExecutor.map`` returns
the results in submission order, so ``rewards[i]`` still belongs to ``completions[i]``.
Size the cap to the number of pairs in ``SOAR_VM_POOL``: the SOC pool blocks extra
threads in ``acquire()`` until a pair is free (``INTERFACES.md`` §5).
"""

from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

__all__ = [
    "EXCLUDED_BATCH_REWARD",
    "MAX_CASCADE_REWARD",
    "REWARD_NAME",
    "RetryableRoundError",
    "cascade_total",
    "get_reward_funcs",
    "sa_cascade_reward",
    "validate_tool_strategy",
]

#: Registry key used by ``recipe`` YAML ``reward_funcs: [sa_cascade]``.
REWARD_NAME = "sa_cascade"

#: ``R = R_format + R_exec + R_eva - P`` cannot exceed 1 + 1 + 1 - 0 (``INTERFACES.md`` §10.2).
MAX_CASCADE_REWARD = 3.0

#: Success-rate tolerance for the Eq. 19 execution gate.
RS_EXE_TOLERANCE = 1e-9

#: Environment variable that sets how many completions a single reward call may score
#: concurrently (each completion is one SOC round, which costs minutes).
REWARD_CONCURRENCY_ENV = "SECLOOP_REWARD_CONCURRENCY"

#: Default reward concurrency.  Match it to the number of pairs in ``SOAR_VM_POOL``
#: (``INTERFACES.md`` §5): a thread that cannot get a pair waits on the pool instead.
DEFAULT_REWARD_CONCURRENCY = 4

#: Reward handed to **every** completion of a batch that had to be excluded.  A uniform
#: reward gives zero GRPO advantage (see the module docstring and INTERFACES §10.2), so the
#: batch contributes no gradient.  It is deliberately 0.0 and deliberately uniform:
#: per-completion constants would still order the completions against each other.
EXCLUDED_BATCH_REWARD = 0.0


class RetryableRoundError(RuntimeError):
    """A round failed for a **retryable** reason (capacity exhaustion), not on merit.

    Raised instead of scoring the sample ``0.0``: ``INTERFACES.md`` §3.1 distinguishes
    ``429`` from ``200 + success:false`` precisely so a busy VM pool is not mistaken for a
    bad strategy.  :func:`sa_cascade_reward` catches it and neutralises the batch.
    """


# --------------------------------------------------------------------------------------
# Seams. Each helper is intentionally module level so the cascade can be unit-exercised
# without a live SOC or a configured LLM endpoint (see the checks in the report).
# The implementations themselves always come from the shared agent abstractions.
# --------------------------------------------------------------------------------------
def _tool_registry():
    """Return the authoritative tool manager (``INTERFACES.md`` §6)."""
    from open_r1.utils.security_tools import create_security_tools

    return create_security_tools()


def _strategy_executor():
    """Return the SOC transport client (``INTERFACES.md`` §3/§5)."""
    from open_r1.utils.batch_executor import BatchExecutor

    return BatchExecutor()


def _parse_tool_calls(completion_text: str) -> Any:
    """Parse tool calls with the same parser the inference agent uses (``§8``)."""
    from open_r1.utils.llm_judge import extract_tool_calls

    return extract_tool_calls(completion_text)


def _judge_over_defence(alert: str, policy: str) -> float:
    """Evaluate the Eq. 21 penalty; raises when the judge is unusable."""
    from open_r1.utils.llm_judge import judge_over_defence

    return judge_over_defence(alert, policy)


# --------------------------------------------------------------------------------------
# Stage 1 - format reward (Eq. 18)
# --------------------------------------------------------------------------------------
def _completion_text(completion: Any) -> str:
    """Extract the assistant text from a TRL completion.

    Raises:
        TypeError: the payload is not a shape this module understands.
    """
    if isinstance(completion, str):
        return completion
    if isinstance(completion, (list, tuple)) and completion:
        first = completion[0]
        if isinstance(first, dict):
            return str(first.get("content") or "")
    raise TypeError(f"unsupported completion payload: {type(completion).__name__}")


def validate_tool_strategy(completion_text: str, tool_manager: Any) -> Optional[List[Dict[str, Any]]]:
    """Stage 1 of the cascade: JSON validity plus tool-name validity (Eq. 18).

    ``INTERFACES.md`` §10.2 scopes this stage to "JSON 合法性 + 工具名合法".  Deeper
    semantics (required parameters, command rendering, policy safety) belong to the
    SOC, which validates and deploys the strategy in stage 2/3.

    Returns:
        The normalised ``[{"tool": ..., "params": {...}}, ...]`` strategy, or
        ``None`` when the completion fails the format stage.
    """
    try:
        parsed = _parse_tool_calls(completion_text)
    except Exception as exc:  # the shared parser raises StrategyParseError
        logger.debug("format stage: tool-call parsing failed: %s", exc)
        return None

    if isinstance(parsed, dict) and "tool" in parsed:  # tolerate a single bare call
        parsed = [parsed]
    if not isinstance(parsed, list) or not parsed:
        logger.debug("format stage: no tool calls found")
        return None

    try:
        available = set(tool_manager.get_available_tools())
    except Exception as exc:  # pragma: no cover - registry misuse
        logger.error("format stage: tool registry is unusable: %s", exc)
        return None

    strategy: List[Dict[str, Any]] = []
    for call in parsed:
        if not isinstance(call, dict):
            logger.debug("format stage: tool call is not an object: %r", call)
            return None
        tool = call.get("tool")
        if not isinstance(tool, str) or tool not in available:
            logger.debug("format stage: unknown tool %r (known: %s)", tool, sorted(available))
            return None
        # `params` is part of the documented output shape (INTERFACES.md §8) and the
        # SOC cannot deploy a call without it.  Whether the parameters are *semantically*
        # sufficient (e.g. `bash` needs `command`) stays the SOC's decision at stage 2.
        if "params" not in call:
            logger.debug("format stage: tool call %r has no params object", tool)
            return None
        params = call["params"]
        if not isinstance(params, dict):
            logger.debug("format stage: params for %r are not an object: %r", tool, params)
            return None
        strategy.append({"tool": tool, "params": dict(params)})
    return strategy


# --------------------------------------------------------------------------------------
# Stages 2 and 3 - execution and evaluation (Eq. 19, Eq. 20)
# --------------------------------------------------------------------------------------
def _run_strategy(executor: Any, strategy: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Deploy the whole strategy in ONE SOC round trip and return the response.

    ``INTERFACES.md`` §5 requires the combined strategy to be deployed once and
    attacked once; ``BatchExecutor.execute_strategy`` does exactly that.  Every
    failure mode is converted into ``None`` (no measurement) so that an illegal or
    unreachable strategy scores ``R_exec = R_eva = 0.0`` instead of aborting the
    training step:

    * ``StrategyValidationError`` (a ``ValueError``): the registry rejected a tool
      name, a legacy parameter name or a non-IPv4 ``ip`` (``INTERFACES.md`` §6).
    * ``SOCError`` / ``SOCUnavailableError``: transport or protocol failure.

    The one failure that is **not** converted into ``None`` is capacity exhaustion: see
    :class:`RetryableRoundError`.  The policy is read from ``SECLOOP_RETRYABLE_POLICY``
    (``exclude`` by default, ``zero`` to score the round instead).
    """
    # Imported here rather than at module scope: `rewards.py` is imported by the trainer
    # before `open_r1._syspath` has necessarily put the repository root on `sys.path`.
    from agent.tools.batch_executor import SOCBusyError, retryable_policy  # noqa: PLC0415

    try:
        response = executor.execute_strategy(strategy)
    except RetryableRoundError:
        raise
    except ValueError as exc:
        logger.warning("execution stage: strategy rejected by the tool registry: %s", exc)
        return None
    except SOCBusyError as exc:
        if retryable_policy() == "exclude":
            raise RetryableRoundError(str(exc)) from exc
        logger.warning(
            "execution stage: pool capacity exhausted and %s=zero, so this sample is "
            "scored 0.0 (%s)",
            "SECLOOP_RETRYABLE_POLICY",
            exc,
        )
        return None
    except Exception as exc:
        logger.warning("execution stage: SOC round trip failed: %s", exc)
        return None

    if not isinstance(response, dict):
        logger.warning("execution stage: unexpected SOC response type %s", type(response).__name__)
        return None
    if not response.get("success"):
        logger.warning("execution stage: SOC reported failure: %s", response.get("error"))
        return None
    return response


#: Tokens that count as ``rs_service == 1`` (Eq. 12 is strict ``{0, 1}``).
_TRUE_SERVICE_TOKENS = frozenset({"1", "true", "yes", "y", "on", "ok"})


def _service_flag(value: Any) -> int:
    """Read ``rs_service`` strictly as ``{0, 1}`` (Eq. 12).

    Only an exact ``1``/``True`` counts as "service available".  Everything else --
    ``0``, a non-binary number, an unparsable string, ``None`` -- is ``0``.  The
    validator only ever emits ``0`` or ``1``, so anything else means the feedback did
    not come from it, and guessing in the optimistic direction is how a disrupted
    service would earn evaluation credit.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return 1 if value == 1 else 0
    if isinstance(value, float):
        return 1 if value == 1.0 else 0
    if isinstance(value, str):
        return 1 if value.strip().lower() in _TRUE_SERVICE_TOKENS else 0
    return 0


def _extract_measurement(
    response: Optional[Dict[str, Any]],
) -> Optional[Tuple[float, float, int]]:
    """Return ``(rs_exe, rs_attack, rs_service)`` from a SOC response, or ``None``.

    ``execute_strategy`` relays the §4 fields both inside ``feedback`` and at the top
    level, and it deliberately never substitutes ``0.0`` for a field the SOC omitted.
    A *missing* measurement must therefore stay missing: defaulting ``rs_attack`` to
    ``0.0`` would silently award the maximum evaluation reward (``1 - 0``) to a round
    that was never measured - the mirror image of the "empty stages must be 0.0, not
    1.0" rule in ``INTERFACES.md`` §4.2.

    A missing ``rs_service`` behaves the same way and for the same reason: it gates
    ``R_eva``, so defaulting it to ``1`` would hand full evaluation credit to a round
    whose service availability was never probed.  Absent evidence of a healthy
    service therefore counts as ``0`` ("no probe, no credit", the validator's own
    rule in Eq. 12) and is reported at ``WARNING`` level.
    """
    if not isinstance(response, dict):
        return None

    sources: List[Dict[str, Any]] = []
    feedback = response.get("feedback")
    if isinstance(feedback, dict):
        sources.append(feedback)
    sources.append(response)

    for source in sources:
        raw_exe = source.get("rs_exe")
        raw_attack = source.get("rs_attack")
        if raw_exe is None or raw_attack is None:
            continue
        try:
            rs_exe = float(raw_exe)
            rs_attack = float(raw_attack)
        except (TypeError, ValueError):
            continue
        if source.get("rs_service") is None:
            # `rs_service` is one of the vector's components (Eq. 12/13): a response that
            # omits it is not a complete measurement, so treat the round as unmeasured
            # rather than reading the missing field as "service down" or "service up".
            # `R_eva` carries no `rs_service` factor, so the "unmeasured" outcome cannot
            # come from the arithmetic: it is stated here as an explicit skip.
            logger.warning(
                "reward: feedback carries no rs_service, so this is not a complete "
                "feedback vector; the round is UNMEASURED, so R_exec and R_eva are 0.0 "
                "(Eq. 12 is never inferred)"
            )
            continue
        return rs_exe, rs_attack, _service_flag(source.get("rs_service"))
    return None


def cascade_total(r_format: float, r_exec: float, r_eva: float, penalty: float) -> float:
    """``R = R_format + R_exec + R_eva - P`` clipped to ``[0, 3]`` (``§10.2``)."""
    total = float(r_format) + float(r_exec) + float(r_eva) - float(penalty)
    return min(max(total, 0.0), MAX_CASCADE_REWARD)


def _reward_concurrency(completion_count: int) -> int:
    """How many rounds to run at once: ``SECLOOP_REWARD_CONCURRENCY``, capped by the batch.

    An unparsable or ``< 1`` value falls back to :data:`DEFAULT_REWARD_CONCURRENCY` with a
    warning instead of turning the reward call into a crash.  The result is never below
    ``1`` (``ThreadPoolExecutor`` rejects zero workers) and is otherwise capped at
    ``completion_count`` (there is nothing to run beyond that).
    """
    raw = os.getenv(REWARD_CONCURRENCY_ENV, str(DEFAULT_REWARD_CONCURRENCY)).strip()
    try:
        configured = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "%s=%r is not an integer; using the default of %d",
            REWARD_CONCURRENCY_ENV,
            raw,
            DEFAULT_REWARD_CONCURRENCY,
        )
        configured = DEFAULT_REWARD_CONCURRENCY
    if configured < 1:
        logger.warning(
            "%s=%r is below 1; using the default of %d",
            REWARD_CONCURRENCY_ENV,
            raw,
            DEFAULT_REWARD_CONCURRENCY,
        )
        configured = DEFAULT_REWARD_CONCURRENCY
    return max(1, min(configured, completion_count))


# --------------------------------------------------------------------------------------
# The registered reward function
# --------------------------------------------------------------------------------------
def sa_cascade_reward(completions: List[Any], alerts: List[str], **kwargs: Any) -> List[float]:
    """Four-stage SA-GRPO cascade reward (paper Eq. 18-21).

    Args:
        completions: TRL completions; each item is a message list whose first
            entry carries the assistant text.
        alerts: the ``alerts`` dataset column, aligned with ``completions``.
        **kwargs: extra dataset columns forwarded by the trainer.

    Returns:
        One reward in ``[0, 3]`` per completion.

    Raises:
        PenaltyJudgeUnavailableError: the penalty judge has no endpoint.
        PenaltyJudgeError: the penalty judge call or response failed.
    """
    if isinstance(alerts, str):  # defensive: a single un-batched prompt
        alerts = [alerts]
    if len(alerts) != len(completions):
        logger.warning(
            "execution stage: %d alerts for %d completions; the penalty judge will see an empty alert",
            len(alerts),
            len(completions),
        )

    tool_manager = _tool_registry()
    executor = _strategy_executor()

    concurrency = _reward_concurrency(len(completions))
    logger.debug(
        "scoring %d completion(s) with up to %d concurrent SOC round(s)",
        len(completions),
        concurrency,
    )

    def _score_one(index: int) -> Tuple[float, bool]:
        """Score one completion and return ``(reward, excluded)``.

        ``excluded`` travels through the return value instead of a shared list: the
        indices run on worker threads, so appending to shared state here would race.
        """
        alert_text = alerts[index] if index < len(alerts) else ""

        try:
            completion_text = _completion_text(completions[index])
        except TypeError as exc:
            # One unreadable payload must not abort the whole training step.  Every
            # other failure mode in this module degrades to 0.0/None (see the failure
            # policy in the module docstring), and TRL calls this function per batch,
            # so a raise here would take the run down instead of scoring one sample.
            logger.warning("completion %d: unreadable payload (%s) -> reward 0.0", index, exc)
            return 0.0, False

        strategy = validate_tool_strategy(completion_text, tool_manager)
        if strategy is None:
            # Format gate failed -> the cascade scores exactly 0.0 (INTERFACES.md §10.2).
            logger.debug("completion %d: format gate failed -> reward 0.0", index)
            return 0.0, False

        r_format = 1.0
        r_exec = 0.0
        r_eva = 0.0

        try:
            response = _run_strategy(executor, strategy)
        except RetryableRoundError as exc:
            # Our problem, not the policy's: the pool was busy for the whole retry budget.
            # Scoring this 0.0 would teach the policy that a good strategy failed, so the
            # sample is EXCLUDED instead.  The flag is returned and the whole batch is
            # neutralised at the end of this function.
            logger.warning("completion %d: %s", index, exc)
            return 0.0, True

        measurement = _extract_measurement(response)
        if measurement is None:
            logger.warning(
                "completion %d: no usable rs_exe/rs_attack measurement, so R_exec and R_eva are 0.0 "
                "(is the SOC server running, and did it return a feedback vector?)",
                index,
            )
        else:
            rs_exe, rs_attack, rs_service = measurement
            r_exec = 1.0 if rs_exe >= 1.0 - RS_EXE_TOLERANCE else 0.0
            # THE ONLY polarity inversion in the project (INTERFACES.md §4/§10.2):
            # rs_attack is the raw Eq. 11 measurement (1.0 = attack succeeded),
            # so the defensive reward is its complement.
            #
            # Eq. 20 is `R_eva(o_i) = W_BATTLE-FIELD(o_i)`, "the absence of warning alarms".
            # If the attack is blocked, the strategy scores the point -- full stop.  No
            # `rs_service` factor: gating this on Eq. 12 would make the evaluation reward
            # conditional on our own service probe.
            #
            # Consequence, stated rather than hidden: a strategy that blocks the attack by
            # breaking the blue-team service also earns `R_eva = 1.0`, which conflicts with
            # §IV-D's gloss that a *correct* strategy causes "no disruption".
            #
            # Nothing inside this function counterbalances that.  `F_i` (Eq. 13) contains
            # `rs_service`, but `cascade_total` never reads `F_i` -- the total is
            # `R_format + R_exec + R_eva - P`, and `rs_service` is unpacked above only to
            # log it and to detect an incomplete vector.  So a strategy that kills the
            # target and one that blocks it cleanly receive the *same* reward.
            # Only `R_exec` (Eq. 19, was the strategy deployable at all) and the Eq. 21
            # judge (`P`, which needs an LLM endpoint) stand between them.
            # If this ever needs the §IV-D reading back, gate here again -- and change
            # `docs/INTERFACES.md` §10.2 with it, because that is the frozen contract.
            r_eva = 1.0 - rs_attack
            logger.debug(
                "completion %d: rs_exe=%s rs_attack=%s rs_service=%s -> R_exec=%s R_eva=%s "
                "(Eq. 20 is not gated on rs_service)",
                index,
                rs_exe,
                rs_attack,
                rs_service,
                r_exec,
                r_eva,
            )

        penalty = _judge_over_defence(alert_text, json.dumps(strategy, ensure_ascii=False))
        total = cascade_total(r_format, r_exec, r_eva, penalty)
        logger.debug(
            "completion %d: R_format=%s R_exec=%s R_eva=%s P=%s -> R=%s",
            index,
            r_format,
            r_exec,
            r_eva,
            penalty,
            total,
        )
        return total, False

    # `map` preserves submission order even when the rounds finish out of order, so
    # `rewards[i]` still corresponds to `completions[i]`.
    with ThreadPoolExecutor(
        max_workers=concurrency, thread_name_prefix="secloop-reward"
    ) as pool:
        scored = list(pool.map(_score_one, range(len(completions))))

    rewards: List[float] = [reward for reward, _ in scored]
    excluded: List[int] = [
        index for index, (_, was_excluded) in enumerate(scored) if was_excluded
    ]

    if excluded:
        # Exclude, do not score.  A retryable transport failure is not a verdict on any
        # strategy, and TRL's reward contract is "one float per completion" -- there is no
        # way to drop a single sample from here.  So the whole call is neutralised: every
        # completion in the batch gets the SAME reward, and in GRPO an identical reward
        # across a group gives zero advantage, i.e. zero gradient.  Nothing is learned from
        # this batch, and nothing false is learned either.
        #
        # The cost is real and is therefore logged: one busy sample costs the whole batch a
        # training step.  That is the deliberate trade against teaching the policy that a
        # good strategy failed.
        #
        # Verified against the pinned TRL source rather than assumed: `grpo_trainer.py`
        # computes `advantages = rewards - mean_grouped_rewards`, dividing by the group std
        # only when `scale_rewards` is on -- and the SA-GRPO recipe sets it off.  A uniform
        # batch therefore has mean == every reward, so advantage == 0 and no gradient flows.
        # Do NOT "simplify" this to `float("nan")`: TRL combines reward functions with
        # `nansum`, which treats a lone NaN as 0, so an excluded sample would silently come
        # back as a zero-scored one -- the exact outcome this branch exists to avoid.
        logger.warning(
            "excluded %d of %d completion(s) in this batch after the retry budget: pool "
            "capacity was exhausted (HTTP 429). The whole batch is neutralised -- uniform "
            "reward, therefore zero GRPO advantage -- instead of scoring those samples 0.0. "
            "Set %s=zero to score such rounds instead.",
            len(excluded),
            len(completions),
            "SECLOOP_RETRYABLE_POLICY",
        )
        return [EXCLUDED_BATCH_REWARD] * len(completions)

    return rewards


def get_reward_funcs(script_args: Any) -> List[Callable]:
    """Resolve ``script_args.reward_funcs`` to callables.

    ``sa_cascade`` is the only reward the paper's recipe uses; the registry is kept
    deliberately minimal so no superseded duplicate can be selected by accident.
    """
    registry: Dict[str, Callable] = {REWARD_NAME: sa_cascade_reward}
    resolved: List[Callable] = []
    for name in script_args.reward_funcs:
        if name not in registry:
            raise ValueError(
                f"Unknown reward function {name!r}. Available: {sorted(registry)}. "
                "The SA-GRPO recipe uses `sa_cascade` (INTERFACES.md §10.1)."
            )
        resolved.append(registry[name])
    return resolved
