# SPDX-License-Identifier: Apache-2.0
"""Policy Execution Validator (PEV) for SecLoop.

Implements the three-dimensional feedback vector of
*Advancing LLM-Based Security Automation With Customized Group Relative Policy
Optimization for Zero-Touch Networks* (IEEE JSAC vol. 44, 2026, pp. 2669-2686,
DOI 10.1109/JSAC.2025.3643844), Section II-B-3, Eqs. (10)-(13):

    RS_i = {rs_exe(S_i), rs_attack(S_i), rs_service(S_i)}
    F_i  = rs_exe(S_i) + rs_attack(S_i) + rs_service(S_i)

Measurement and polarity are deliberately separated (see docs/INTERFACES.md §4):

``rs_exe``
    ``mean(tool.success)`` over every tool of the strategy (Eq. 10).
``rs_attack``
    ``mean(stage.success)`` -- the **raw** Eq. 11 measurement of how much of the
    attack succeeded.  It is **never inverted here**.  The polarity
    ``R_eva = 1 - rs_attack`` belongs to the reward layer only
    (``training/src/open_r1/rewards.py``).  That form is this repository's estimator of
    Eq. 20's "absence of alarms"; the paper names the term (``W_BATTLE-FIELD``) without
    giving an estimator.  ``rs_service`` is **not** a gate on it -- it is
    measured here, reported, and counted in ``F_i``.
``rs_service``
    Strictly ``{0, 1}``, derived from a **real** service probe executed by the
    caller (``battlefield/soc_server.py``).  A heuristic proxy -- e.g. "some blue
    command succeeded and the attack score is low" -- is deliberately rejected.
``defense_effectiveness``
    ``1 - rs_attack``, emitted as a **read-only convenience field** for logs and
    plots.  It must never be substituted for ``rs_attack`` inside Eq. 13.

``validate()`` is a **pure function**: no network I/O, no VM access, no global
state.  That is what makes the feedback maths unit-testable without the lab.

Empty-input policy: an empty stage list yields
``rs_attack = 0.0`` plus a ``WARNING``; returning ``1.0`` would let an attack
that never ran score like a perfect defence.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "ABORT_KINDS",
    "MAX_OUTPUT_CHARS",
    "PolicyExecutionValidator",
    "TARGET_UNREACHABLE",
    "coerce_success_flag",
    "compute_rs_attack",
    "compute_rs_exe",
    "compute_rs_service",
    "validate",
]

#: Tool output is echoed into the HTTP feedback document; cap it so a verbose
#: tool can never blow up the SOC response.
MAX_OUTPUT_CHARS = 4000

#: The authoritative set of ``abort_kind`` values (``docs/INTERFACES.md`` §2.1).
#:
#: The attack script holds its own copy because it runs **on the attacker VM** and must
#: stay self-contained; ``tests/lab/test_abort_kind_contract.py`` pins the two sets equal
#: so the duplication cannot drift. This side is canonical because it is the side that
#: *consumes* the field.
ABORT_KINDS = frozenset(
    {
        "target-unreachable",  # what a successful block looks like (Eq. 11 ⇒ 0.0)
        "oracle-unconfirmed",  # reachable, but the SQLi oracle cannot be established
        "dependency-missing",  # the probe's own prerequisites are absent
        "config-invalid",  # the invocation is wrong (target outside the lab networks)
        "unclassified",  # anything else -- consumers must treat it as unmeasured
    }
)

#: The one kind that counts as "the defence kept the attacker out".
TARGET_UNREACHABLE = "target-unreachable"

_TRUE_TOKENS = frozenset({"1", "true", "yes", "y", "on", "success", "succeeded", "ok"})
_FALSE_TOKENS = frozenset({"0", "false", "no", "n", "off", "failure", "failed", "error", ""})


def coerce_success_flag(value: Any, *, field: str = "success") -> bool:
    """Public alias of the SOC-wide "what counts as success" rule.

    Exported so RTC and PEV cannot drift apart on what a successful stage or a
    successful tool call means (docs/INTERFACES.md §2.1 describes both flags the
    same way: a JSON boolean).
    """
    return _coerce_bool(value, field=field)


def _coerce_bool(value: Any, *, field: str) -> bool:
    """Coerce a JSON-ish flag to ``bool``, logging anything ambiguous.

    The attack script emits real JSON booleans (docs/INTERFACES.md §2.1), so an
    unexpected value is reported and treated as ``False`` instead of being
    guessed -- guessing is how the RTC fabricates successful
    stages.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value in (0, 1):
            return bool(value)
        logger.warning("PEV: non-binary integer for '%s': %r -> False", field, value)
        return False
    if isinstance(value, float):
        if value in (0.0, 1.0):
            return bool(value)
        logger.warning("PEV: non-binary float for '%s': %r -> False", field, value)
        return False
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _TRUE_TOKENS:
            return True
        if token in _FALSE_TOKENS:
            return False
        logger.warning("PEV: unrecognised flag text for '%s': %r -> False", field, value)
        return False
    if value is None:
        return False
    logger.warning(
        "PEV: unexpected type for '%s': %s -> False", field, type(value).__name__
    )
    return False


def _as_float(value: Any) -> float | None:
    """Return ``float(value)`` or ``None`` when the value is not numeric."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _normalize_stages(stages: Any, *, field: str) -> list[dict[str, Any]]:
    """Normalise a stage collection to ``[{name, success[, weight]}, ...]``.

    Unknown entries are **counted as failed**, never dropped and never invented, and every
    anomaly is logged.  ``success`` is always present so the Eq. 11 mean is well defined.

    Dropping is asymmetric: a malformed *tool* result is
    counted as a failure below, while a malformed *stage* would shrink the Eq. 11
    denominator ``m``.  Since a dropped entry is as likely to have been a failure as a
    success, shrinking ``m`` moves the mean in the flattering direction -- the exact
    failure mode the ``rs_exe`` path refuses.
    """
    if stages is None:
        return []
    if isinstance(stages, (str, bytes, Mapping)):
        logger.warning(
            "PEV: %s must be a list of stage objects, got %s; ignoring",
            field,
            type(stages).__name__,
        )
        return []
    if not isinstance(stages, Sequence):
        if isinstance(stages, Iterable):
            stages = list(stages)
        else:
            logger.warning(
                "PEV: %s is not iterable (%s); ignoring", field, type(stages).__name__
            )
            return []

    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(stages):
        if not isinstance(raw, Mapping):
            # Not a skip: see the docstring.  The contract fixes the stage list, so an
            # unparsable entry is a violation of the contract, and "we could not read this
            # stage" must not be read as "this stage is not counted".
            logger.warning(
                "PEV: %s[%d] is not an object (%s); counting it as a failed stage so the "
                "Eq. 11 denominator stays honest",
                field,
                index,
                type(raw).__name__,
            )
            normalized.append({"name": f"stage_{index}", "success": False})
            continue
        name = raw.get("name", raw.get("stage", ""))
        if not isinstance(name, str) or not name.strip():
            # Never drop a stage that carries a measurable `success`: Eq. 11 only
            # needs the flag.  A transparent placeholder keeps the denominator
            # honest, and the contract violation is logged.
            logger.warning(
                "PEV: %s[%d] has no usable 'name'; using placeholder", field, index
            )
            name = f"stage_{index}"
        item: dict[str, Any] = {
            "name": name.strip(),
            "success": _coerce_bool(
                raw.get("success"), field=f"{field}[{index}].success"
            ),
        }
        weight = _as_float(raw.get("weight"))
        if weight is not None:
            item["weight"] = weight
        normalized.append(item)
    return normalized


def _normalize_tools(tool_results: Any) -> list[dict[str, Any]]:
    """Normalise BTC output to the feedback shape ``[{tool, success, output, error}]``."""
    if tool_results is None:
        return []
    if isinstance(tool_results, (str, bytes, Mapping)):
        logger.warning(
            "PEV: tool_results must be a list, got %s; ignoring",
            type(tool_results).__name__,
        )
        return []
    if not isinstance(tool_results, Sequence):
        if isinstance(tool_results, Iterable):
            tool_results = list(tool_results)
        else:
            logger.warning(
                "PEV: tool_results is not iterable (%s); ignoring",
                type(tool_results).__name__,
            )
            return []

    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(tool_results):
        if not isinstance(raw, Mapping):
            # Count it as a FAILED tool instead of dropping it.  Eq. 10 divides by
            # ``l``, the number of tool calls, so skipping an entry shrinks the
            # denominator: with 4 calls where one result came back malformed, the
            # remaining 3/3 would score ``rs_exe = 1.0`` and clear the R_exec gate.
            # Dropping unparsable input therefore *raises* the execution reward, which
            # is the wrong direction -- an unverifiable deployment is not a success.
            logger.warning(
                "PEV: tool_results[%d] is not an object (%s); counted as a failed tool so "
                "Eq. 10's denominator stays the number of tool calls",
                index,
                type(raw).__name__,
            )
            normalized.append(
                {
                    "tool": "",
                    "success": False,
                    "output": "",
                    "error": "malformed tool result (not an object)",
                }
            )
            continue
        tool = raw.get("tool", raw.get("tool_name", ""))
        output = raw.get("output")
        if output is None:
            output = ""
        elif not isinstance(output, str):
            output = str(output)
        if len(output) > MAX_OUTPUT_CHARS:
            truncated = len(output) - MAX_OUTPUT_CHARS
            output = output[:MAX_OUTPUT_CHARS] + f"... [truncated {truncated} chars]"
        error = raw.get("error")
        normalized.append(
            {
                "tool": str(tool) if tool else "",
                "success": _coerce_bool(
                    raw.get("success"), field=f"tool_results[{index}].success"
                ),
                "output": output,
                "error": None if error is None else str(error),
            }
        )
    return normalized


def compute_rs_exe(tool_results: Sequence[Mapping[str, Any]] | None) -> float:
    """Eq. (10): ``rs_exe(S_i) = (1/l) * sum_j f_exe(t_j)``.

    ``l`` is the number of tool calls in the strategy.  An empty strategy yields
    ``0.0``: with no tools deployed there is nothing to execute, and Eq. 10 is
    undefined rather than perfect.

    The input is normalised first, so this is safe to call with raw BTC output as
    well as with already-normalised feedback: an entry that is not an object counts
    as a *failed* tool.  Indexing ``r.get("success")`` directly would both crash on
    such an entry and -- through a dropping ``_normalize_tools`` -- let a malformed
    result shrink ``l`` and so *raise* ``rs_exe``.
    """
    tools = _normalize_tools(tool_results)
    if not tools:
        logger.warning("PEV: strategy contains no tool results -> rs_exe=0.0")
        return 0.0
    successes = sum(
        1 for r in tools if _coerce_bool(r.get("success"), field="tool.success")
    )
    return round(successes / len(tools), 4)


def compute_rs_attack(stages: Sequence[Mapping[str, Any]] | None) -> float:
    """Eq. (11): ``rs_attack(S_i) = (1/m) * sum_j f_exe(p_j)`` -- raw, never inverted.

    An empty stage list means the attack produced no measurable stage at all
    (broken RTC, crashed/unparseable attack output).  That must yield ``0.0``,
    not ``1.0``.

    A stage that is not a mapping counts as a **failure**, and it still counts towards
    ``m`` -- see :func:`_normalize_stages`.  This function is
    exported, so a caller that skipped normalisation must not be able to crash the SOC or
    shrink the denominator; a stray string would do both (``AttributeError``, and a
    smaller ``m``).
    """
    if not stages:
        logger.warning(
            "PEV: no attack stages reported -> rs_attack=0.0 (Eq. 11 raw value; "
            "an attack that never ran must not score as a successful defence)"
        )
        return 0.0
    successes = 0
    for stage in stages:
        if not isinstance(stage, Mapping):
            logger.warning(
                "PEV: stage %r is not an object (%s); counting it as failed",
                stage,
                type(stage).__name__,
            )
            continue
        if _coerce_bool(stage.get("success"), field="stage.success"):
            successes += 1
    return round(successes / len(stages), 4)


def compute_rs_service(service_probe: Mapping[str, Any] | None) -> int:
    """Eq. (12): ``rs_service(S_i) = f_service(E_BVM, E_RVM, S_i)`` in ``{0, 1}``.

    The caller performs the real probe (HTTP GET on the target app plus
    reachability of the attacker VM) and passes the two booleans in.  Anything
    that cannot be verified counts as ``0`` -- service availability is never
    inferred from the strategy or from the attack score.
    """
    if not isinstance(service_probe, Mapping):
        logger.warning(
            "PEV: no service probe supplied (%s) -> rs_service=0 (no probe, no credit)",
            type(service_probe).__name__,
        )
        return 0
    target_http = _coerce_bool(
        service_probe.get("target_http"), field="service_probe.target_http"
    )
    attacker_reachable = _coerce_bool(
        service_probe.get("attacker_reachable"), field="service_probe.attacker_reachable"
    )
    value = 1 if (target_http and attacker_reachable) else 0
    if value == 0:
        logger.warning(
            "PEV: service probe failed (target_http=%s, attacker_reachable=%s) -> rs_service=0",
            target_http,
            attacker_reachable,
        )
    return value


def validate(
    tool_results: Sequence[Mapping[str, Any]] | None,
    attack_result: Mapping[str, Any] | None,
    service_probe: Mapping[str, Any] | None,
    pre_attack_stages: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute the full feedback document of docs/INTERFACES.md §3.1.

    Pure function: no network calls, no VM access, no mutation of its inputs.

    Args:
        tool_results: per-tool results from ``BlueTeamController.deploy_strategy``
            (one entry per tool of the whole strategy -- Eq. 10 denominator).
        attack_result: result from ``RedTeamController.run_attack`` (or a raw
            ``[RESULT]`` payload); only ``stages``/``error`` are consumed.
        service_probe: ``{"target_http": bool, "attacker_reachable": bool}`` from
            the real probe in ``soc_server.py``.
        pre_attack_stages: optional diagnostic sample taken before the strategy
            was deployed (docs/INTERFACES.md §5 step 1).

    Returns:
        ``{rs_exe, rs_attack, rs_service, F_i, defense_effectiveness, stages,
        tools, service_probe, pre_attack_stages}``.
    """
    tools = _normalize_tools(tool_results)

    if isinstance(attack_result, Mapping):
        raw_stages = attack_result.get("stages")
        # ``error`` means "no measurement at all"; ``attack_error`` means the attack
        # ran but could not progress (packets dropped by block_ip, unconfirmed
        # oracle, ...).  Both belong in the log.
        attack_error = attack_result.get("error") or attack_result.get("attack_error")
        if attack_error:
            logger.warning("PEV: attack reported an error: %s", attack_error)
    else:
        if attack_result is not None:
            logger.warning(
                "PEV: attack_result is not an object (%s); treating stages as empty",
                type(attack_result).__name__,
            )
        raw_stages = None

    stages = _normalize_stages(raw_stages, field="attack_result.stages")
    pre_stages = _normalize_stages(pre_attack_stages, field="pre_attack_stages")

    probe_in: Mapping[str, Any] = (
        service_probe if isinstance(service_probe, Mapping) else {}
    )
    probe_out = {
        "target_http": _coerce_bool(
            probe_in.get("target_http"), field="service_probe.target_http"
        ),
        "attacker_reachable": _coerce_bool(
            probe_in.get("attacker_reachable"),
            field="service_probe.attacker_reachable",
        ),
    }

    rs_exe = compute_rs_exe(tools)
    rs_attack = compute_rs_attack(stages)
    rs_service = compute_rs_service(probe_out)
    f_i = round(rs_exe + rs_attack + rs_service, 4)

    feedback = {
        "rs_exe": rs_exe,
        "rs_attack": rs_attack,
        "rs_service": rs_service,
        "F_i": f_i,
        # Read-only convenience value; the reward layer computes 1 - rs_attack itself.
        "defense_effectiveness": round(1.0 - rs_attack, 4),
        "stages": stages,
        "tools": tools,
        "service_probe": probe_out,
        "pre_attack_stages": pre_stages,
    }
    logger.info(
        "PEV: rs_exe=%.4f rs_attack=%.4f rs_service=%d F_i=%.4f (tools=%d, stages=%d)",
        rs_exe,
        rs_attack,
        rs_service,
        f_i,
        len(tools),
        len(stages),
    )
    return feedback


class PolicyExecutionValidator:
    """Stateless facade over the pure functions above.

    Kept for callers that prefer an object, and so the
    SOC server can hold a single validator instance while the maths stays a pure
    function.  Instances hold no state and perform no I/O.
    """

    def validate(
        self,
        tool_results: Sequence[Mapping[str, Any]] | None,
        attack_result: Mapping[str, Any] | None,
        service_probe: Mapping[str, Any] | None,
        pre_attack_stages: Sequence[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """See :func:`validate`."""
        return validate(tool_results, attack_result, service_probe, pre_attack_stages)

    @staticmethod
    def compute_rs_exe(tool_results: Sequence[Mapping[str, Any]] | None) -> float:
        """See :func:`compute_rs_exe`."""
        return compute_rs_exe(tool_results)

    @staticmethod
    def compute_rs_attack(stages: Sequence[Mapping[str, Any]] | None) -> float:
        """See :func:`compute_rs_attack`."""
        return compute_rs_attack(stages)

    @staticmethod
    def compute_rs_service(service_probe: Mapping[str, Any] | None) -> int:
        """See :func:`compute_rs_service`."""
        return compute_rs_service(service_probe)
