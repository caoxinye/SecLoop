# SPDX-License-Identifier: Apache-2.0
"""One ``POST /execute_ability`` round -- the fixed timing of ``docs/INTERFACES.md`` §5.

This module issues **one** HTTP round trip per round, not one per tool: one per tool would
run a complete red/blue cycle plus a snapshot restore for every tool, so a composite
strategy would never be evaluated as one defence (paper Eq. 8).  A round is exactly::

    1. optional pre-attack sample                 RTC.run_attack()   -> pre_attack_stages
    2. BTC.deploy_strategy(tools, blue_vm)        ONE pass over the WHOLE strategy
    3. RTC.run_attack()                           ONE attack against that deployment
    4. PEV.validate(...)                          rs_exe (step 2) + rs_attack (step 3) + rs_service (real probe)
    5. BTC.restore_snapshot(blue_vm)              environment back to a clean state
    6. pool release

``rs_exe`` and ``rs_attack`` therefore come from the **same** deployment and the
**same** attack run.

Response invariant (resolves an ambiguity in ``docs/INTERFACES.md`` §3.1)
-----------------------------------------------------------------------
``feedback`` is non-null **iff** the round was measured: the strategy was
deployed, the attack produced a usable ``[RESULT]`` stage list, the probe ran and
the environment was rolled back.  A round that could **not** be measured
(unparsable/missing ``[RESULT]``, empty stage list, dead VM, failed snapshot
restore) returns ``success: false``, ``error: <reason>`` and ``feedback: null``,
so no caller can mistake "we could not measure the attack" for the genuine
``rs_attack = 0.0`` of a successful defence.

A **measured** attack whose stages are all ``false`` *is* a working defence, so it
returns ``success: true`` with ``rs_attack = 0.0``; the attack script's own
message ("oracle not confirmed" after ``block_ip``, "target unreachable", ...) is
surfaced in the additive ``attack_error`` field and logged, while ``rs_service``
separates "the attack was blocked" (``1``) from "the target is gone" (``0``).

``target_ip`` is additionally required to sit inside ``SOC_LAB_NETWORKS``
(default ``192.168.57.0/24,127.0.0.0/8``, the same guard the attack script
applies).  A refusal by the producer is an operator error, not a defence, and
must not be measured as "all stages false".

Flask is deliberately not imported here, so the whole round can be exercised
with fake controllers and no VM stack.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from .blue_team_controller import BlueTeamController, ToolSpecError
from .policy_execution_validator import PolicyExecutionValidator
from .red_team_controller import RedTeamController
from .service_probe import DEFAULT_TARGET_URL, ServiceProbe
from .vagrant_driver import VagrantSnapshotError
from .vm_pool import (
    DEFAULT_POOL_TIMEOUT_S,
    POOL_TIMEOUT_ENV,
    VmPair,
    VmPool,
    VmPoolExhausted,
)

logger = logging.getLogger(__name__)

__all__ = [
    "PipelineConfig",
    "RequestError",
    "RoundRequest",
    "SocRoundPipeline",
    "resolve_causation",
]

PRE_ATTACK_SAMPLE_ENV = "SOC_PRE_ATTACK_SAMPLE"
REQUIRE_SNAPSHOT_ENV = "SOC_REQUIRE_SNAPSHOT"
BLUE_IP_ENV = "SOC_BLUE_IP"
LAB_NETWORKS_ENV = "SOC_LAB_NETWORKS"
DEFAULT_BLUE_IP = "192.168.57.200"
# NOTE: ``POOL_TIMEOUT_ENV`` and ``DEFAULT_POOL_TIMEOUT_S`` are *imported* from
# ``vm_pool`` above, which owns the pool.  Importing rather than re-declaring them as
# literals keeps one definition, so the exported names cannot disagree about the
# pool's own timeout.
#: Mirrors the attack script's own guard (``docs/INTERFACES.md`` §1): the SOC only
#: ever points the red VM at the isolated lab, and it says so *before* spending a
#: VM pair on a target the producer would refuse anyway.
DEFAULT_LAB_NETWORKS: tuple[str, ...] = ("192.168.57.0/24", "127.0.0.0/8")


def resolve_causation(
    *,
    post_unreached: bool,
    pre_attack_sample: bool,
    pre_result: Mapping[str, Any] | None,
) -> bool | None:
    """Did the deployed defence *cause* an unreachable attack? (the pre-attack control)

    "The attack never ran" counts as blocked (INTERFACES §2.1). But an unreachable
    target has two very different explanations, and an all-false stage list cannot tell
    them apart:

    * the strategy we just deployed cut the attacker off -- a genuine block, credit it;
    * the lab was already broken before the strategy ran -- our fault, credit nothing.

    The pre-attack sample is the control that separates them: the same attack is run
    **before** deployment, and its outcome is compared with the post-deployment one.

    Returns:
        ``True`` -- the pre-attack reached the target and the post-attack did not, so the
        deployment is the only thing that changed. Proven.
        ``False`` -- the pre-attack could not reach the target either, so the
        unreachability predates the defence. The round must be **unmeasured**, not credited.
        ``None`` -- nobody checked (no control enabled, the control itself was unusable, or
        the post-attack was reachable in the first place). Unproven, and reported as such.

    Pure and injectable, so the three cases are unit-testable without a lab.
    """
    if not post_unreached:
        return None
    if not pre_attack_sample or pre_result is None:
        return None
    if not pre_result.get("success"):
        # The control produced no measurement of its own, so it cannot answer the question.
        return None
    if pre_result.get("attack_unreached"):
        return False
    return True


def _truthy(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _host_from_url(url: str) -> str | None:
    """Extract the host from ``http://host:port/path`` without importing anything heavy."""
    text = (url or "").strip()
    if "//" in text:
        text = text.split("//", 1)[1]
    text = text.split("/", 1)[0]
    if not text:
        return None
    if text.startswith("["):  # bracketed IPv6
        return text[1:].split("]", 1)[0]
    return text.split(":", 1)[0] or None


class RequestError(ValueError):
    """Raised when a request body cannot be interpreted as a strategy round."""


@dataclass(frozen=True)
class PipelineConfig:
    """Round-level switches (all overridable by environment variables)."""

    pre_attack_sample: bool = False
    require_snapshot: bool = True
    default_attack_mode: str = "sqli"
    blue_ip: str = DEFAULT_BLUE_IP
    pool_timeout_s: float = DEFAULT_POOL_TIMEOUT_S
    lab_networks: tuple[str, ...] = DEFAULT_LAB_NETWORKS

    @classmethod
    def from_env(cls) -> PipelineConfig:
        """Read ``SOC_*`` environment variables with sane lab defaults."""
        target_url = os.getenv("SOC_TARGET_URL", DEFAULT_TARGET_URL)
        blue_ip = os.getenv(BLUE_IP_ENV) or _host_from_url(target_url) or DEFAULT_BLUE_IP
        try:
            blue_ip = str(ipaddress.ip_address(blue_ip))
        except ValueError:
            logger.warning(
                "%s/%s did not yield an IP address (%r); using %s",
                BLUE_IP_ENV,
                "SOC_TARGET_URL",
                blue_ip,
                DEFAULT_BLUE_IP,
            )
            blue_ip = DEFAULT_BLUE_IP
        raw_networks = os.getenv(LAB_NETWORKS_ENV, "")
        networks: list[str] = []
        for token in raw_networks.split(","):
            token = token.strip()
            if not token:
                continue
            try:
                networks.append(str(ipaddress.ip_network(token, strict=False)))
            except ValueError:
                logger.warning("%s entry %r is not a network; ignored", LAB_NETWORKS_ENV, token)
        if not networks:
            networks = list(DEFAULT_LAB_NETWORKS)
        return cls(
            pre_attack_sample=_truthy(os.getenv(PRE_ATTACK_SAMPLE_ENV)),
            require_snapshot=_truthy(os.getenv(REQUIRE_SNAPSHOT_ENV), default=True),
            default_attack_mode=os.getenv("SOC_ATTACK_MODE", "sqli"),
            blue_ip=blue_ip,
            pool_timeout_s=float(os.getenv(POOL_TIMEOUT_ENV, DEFAULT_POOL_TIMEOUT_S)),
            lab_networks=tuple(networks),
        )


@dataclass(frozen=True)
class RoundRequest:
    """A validated ``/execute_ability`` request."""

    strategy: list[Any]
    attack_mode: str
    red_vm: str
    blue_vm: str
    target_ip: str
    pair_name: str | None = None
    source: str = "strategy"
    warnings: tuple[str, ...] = field(default=())


class SocRoundPipeline:
    """Executes one SOC round against one VM pair from the pool.

    Args:
        pool: VM pair pool (acquire/release is lock-protected there).
        btc: blue-team controller (real one, or a fake in tests).
        rtc: red-team controller.
        pev: policy execution validator (pure).
        probe: real service probe for ``rs_service``.
        config: round switches; defaults to :meth:`PipelineConfig.from_env`.
    """

    def __init__(
        self,
        *,
        pool: VmPool,
        btc: BlueTeamController,
        rtc: RedTeamController,
        pev: PolicyExecutionValidator,
        probe: ServiceProbe,
        config: PipelineConfig | None = None,
    ) -> None:
        self.pool = pool
        self.btc = btc
        self.rtc = rtc
        self.pev = pev
        self.probe = probe
        self.config = config or PipelineConfig.from_env()

    # ----------------------------------------------------------- entry point

    def execute(self, payload: Mapping[str, Any] | None) -> tuple[dict[str, Any], int]:
        """Run one round.

        Returns:
            ``(json_body, http_status)``.  Business failures are HTTP 200 with
            ``success: false`` per ``docs/INTERFACES.md`` §3.1; only capacity
            exhaustion uses another status (429, retry later).
        """
        started = time.monotonic()
        try:
            round_request = self.parse_request(payload)
        except RequestError as exc:
            logger.warning("SOC: rejecting request: %s", exc)
            return self.build_failure(
                attack_mode=(payload or {}).get("attack_mode") or self.config.default_attack_mode,
                error=str(exc),
                elapsed_s=time.monotonic() - started,
                status=200,
            )

        try:
            pair = self.pool.acquire(
                timeout_s=self.config.pool_timeout_s, preferred=round_request.pair_name
            )
        except VmPoolExhausted as exc:
            logger.error("SOC: no VM pair available: %s", exc)
            return self.build_failure(
                attack_mode=round_request.attack_mode,
                error=str(exc),
                elapsed_s=time.monotonic() - started,
                status=429,
            )

        try:
            return self._run_round(round_request, pair, started)
        finally:
            self.pool.release(pair)

    # -------------------------------------------------------- request parsing

    def parse_request(self, payload: Mapping[str, Any] | None) -> RoundRequest:
        """Validate the request body (both the canonical and legacy shapes).

        Raises:
            RequestError: the body cannot be interpreted as a strategy.
        """
        if payload is None:
            raise RequestError("request body must be a JSON object")
        if not isinstance(payload, Mapping):
            raise RequestError(f"request body must be a JSON object, got {type(payload).__name__}")

        warnings: list[str] = []
        source = "strategy"
        if "strategy" in payload and payload.get("strategy") is not None:
            strategy = payload["strategy"]
            if not isinstance(strategy, list):
                raise RequestError(
                    f"'strategy' must be a list of tool calls, got {type(strategy).__name__}"
                )
            if "command" in payload:
                warnings.append("both 'strategy' and legacy 'command' were sent; using 'strategy'")
        elif "command" in payload and str(payload.get("command") or "").strip():
            source = "command"
            strategy = [{"tool": "bash", "params": {"command": str(payload["command"])}}]
        else:
            raise RequestError("request needs either a 'strategy' list or a legacy 'command' string")

        if not strategy:
            warnings.append("'strategy' is empty: no tool will be deployed (rs_exe will be 0.0)")

        attack_mode = payload.get("attack_mode") or self.config.default_attack_mode
        if not isinstance(attack_mode, str):
            raise RequestError("'attack_mode' must be a string")
        if attack_mode not in self.rtc.attack_modes:
            raise RequestError(
                f"unknown attack_mode {attack_mode!r}; available: "
                f"{', '.join(self.rtc.attack_modes) or 'none'}"
            )

        red_vm = payload.get("red_vm") or payload.get("red_vm_name")
        blue_vm = payload.get("blue_vm") or payload.get("blue_vm_name")
        for key, value in (("red_vm", red_vm), ("blue_vm", blue_vm)):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise RequestError(f"{key!r} must be a non-empty string")
        if "red_vm_name" in payload or "blue_vm_name" in payload:
            warnings.append(
                "legacy 'red_vm_name'/'blue_vm_name' keys used; the frozen contract uses "
                "'red_vm'/'blue_vm'"
            )

        target_ip = payload.get("target_ip") or self.config.blue_ip
        try:
            target_ip = str(ipaddress.ip_address(str(target_ip)))
        except ValueError as exc:
            raise RequestError(f"'target_ip' must be an IPv4/IPv6 address: {exc}") from exc

        # The attack script refuses anything outside the isolated lab networks.  A
        # refusal is an operator error, not a defence, so it is rejected here --
        # otherwise a misconfigured target would be *measured* as "attack blocked"
        # (all stages false => rs_attack 0.0).  ``SOC_LAB_NETWORKS`` widens this for
        # additional pairs on other subnets.
        address = ipaddress.ip_address(target_ip)
        allowed = [
            network
            for network in self.config.lab_networks
            if address in ipaddress.ip_network(network, strict=False)
        ]
        if not allowed:
            raise RequestError(
                f"'target_ip' {target_ip} is outside the lab networks "
                f"{', '.join(self.config.lab_networks)}; the SQLi scenario only attacks the "
                f"isolated lab (set {LAB_NETWORKS_ENV} to change this)"
            )

        pair_name = payload.get("pair") or payload.get("pair_id")
        if pair_name is not None and not isinstance(pair_name, str):
            raise RequestError("'pair' must be a string")

        for warning in warnings:
            logger.warning("SOC: %s", warning)
        return RoundRequest(
            strategy=list(strategy),
            attack_mode=attack_mode,
            # Deliberately left EMPTY when the caller did not name a VM.  The *pair*
            # owns the machine names -- a pool entry may legitimately be
            # ``kali2``/``target2`` -- and ``_run_round`` resolves
            # ``round_request.red_vm or pair.red_vm``.  A default here would make
            # ``pair.red_vm``/``pair.blue_vm`` unreachable dead code, and a
            # multi-pair ``SOAR_VM_POOL`` would silently deploy to (and roll the
            # ``target_init`` snapshot of) the wrong machines.
            red_vm=(red_vm or "").strip(),
            blue_vm=(blue_vm or "").strip(),
            target_ip=target_ip,
            pair_name=pair_name,
            source=source,
            warnings=tuple(warnings),
        )

    # ------------------------------------------------------------- the round

    def _run_round(
        self, round_request: RoundRequest, pair: VmPair, started: float
    ) -> tuple[dict[str, Any], int]:
        red_vm = round_request.red_vm or pair.red_vm
        blue_vm = round_request.blue_vm or pair.blue_vm
        attack_mode = round_request.attack_mode
        logger.info(
            "SOC: round on %s starting (attack_mode=%s, tools=%d, target_ip=%s)",
            pair.name,
            attack_mode,
            len(round_request.strategy),
            round_request.target_ip,
        )

        pre_stages: list[Mapping[str, Any]] = []
        pre_result: dict[str, Any] = {}
        tool_results: list[dict[str, Any]] = []
        attack_result: dict[str, Any] = {}
        feedback: dict[str, Any] | None = None
        error: str | None = None
        restore_error: str | None = None
        deployment_started = False

        try:
            # ---- step 1: optional diagnostic sample, BEFORE any deployment ----
            if self.config.pre_attack_sample:
                pre_result = self.rtc.run_attack(
                    attack_mode, red_vm, target_ip=round_request.target_ip
                )
                if pre_result.get("success"):
                    pre_stages = list(pre_result.get("stages") or [])
                    logger.info(
                        "SOC: pre-attack sample captured %d stage(s)%s",
                        len(pre_stages),
                        " (target already unreachable -- the control will veto any credit)"
                        if pre_result.get("attack_unreached")
                        else "",
                    )
                else:
                    logger.warning(
                        "SOC: pre-attack sample failed (%s); continuing without it",
                        pre_result.get("error"),
                    )

            # ---- step 2: deploy the WHOLE strategy in one pass (Eq. 8/10) ----
            deployment_started = True
            tool_results = self.btc.deploy_strategy(round_request.strategy, blue_vm)

            # ---- step 3: attack the deployed strategy exactly once (Eq. 11) ----
            attack_result = self.rtc.run_attack(
                attack_mode, red_vm, target_ip=round_request.target_ip
            )

            # ---- step 3b: did the defence CAUSE an unreachable attack? (pre-attack control) ----
            if attack_result.get("attack_unreached"):
                caused = resolve_causation(
                    post_unreached=True,
                    pre_attack_sample=self.config.pre_attack_sample,
                    pre_result=pre_result,
                )
                attack_result["caused_by_defence"] = caused
                if caused is True:
                    logger.info(
                        "SOC: the pre-attack control reached the target and the post-attack "
                        "did not, so the deployed strategy caused the block (proven)"
                    )
                elif caused is False:
                    error = (
                        "the attack on the target was unreachable both before and after the "
                        "deployment, so this is an environment fault rather than a defence: "
                        "the round is UNMEASURED instead of being credited as a block "
                        f"(pre-attack said abort_kind="
                        f"{pre_result.get('abort_kind')!r}; INTERFACES §2.2)"
                    )
                    logger.warning("SOC: %s", error)
                else:
                    logger.warning(
                        "SOC: the attack was unreachable after deployment but no pre-attack "
                        "control ran, so 'the defence caused it' is UNPROVEN; it is counted "
                        "as a block and flagged (set %s=1 for the control)",
                        PRE_ATTACK_SAMPLE_ENV,
                    )

            # ---- step 4: real service probe + pure validation (Eq. 12/13) ----
            probe_result = self.probe.run()
            feedback = self.pev.validate(
                tool_results,
                attack_result,
                probe_result.as_feedback(),
                pre_attack_stages=pre_stages,
            )
            if not attack_result.get("success"):
                error = str(
                    attack_result.get("error")
                    or "attack produced no measurable [RESULT] payload"
                )
                logger.warning(
                    "SOC: attack was not measurable on %s (%s); the round fails instead of "
                    "reporting a fabricated rs_attack=0.0",
                    red_vm,
                    error,
                )
        except (ToolSpecError, ValueError) as exc:
            error = f"strategy deployment rejected: {exc}"
            logger.error("SOC: %s", error)
        except Exception as exc:  # noqa: BLE001 - a broken lab must not 500 silently
            error = f"{type(exc).__name__}: {exc}"
            logger.exception("SOC: round failed unexpectedly")
        finally:
            # ---- step 5: always roll the blue VM back to a clean state ----
            if deployment_started:
                try:
                    self.btc.restore_snapshot(blue_vm)
                except VagrantSnapshotError as exc:
                    restore_error = str(exc)
                except Exception as exc:  # noqa: BLE001
                    restore_error = f"{type(exc).__name__}: {exc}"
                if restore_error:
                    logger.critical(
                        "SOC: snapshot restore failed on %s (%s); the lab is dirty and the "
                        "next round would measure a polluted VM",
                        blue_vm,
                        restore_error,
                    )

        elapsed = time.monotonic() - started
        score = float(attack_result.get("score") or 0.0)

        if error is None and feedback is not None and restore_error and self.config.require_snapshot:
            error = (
                f"snapshot restore failed ({restore_error}); the environment could not be rolled "
                f"back, so the round is rejected (set {REQUIRE_SNAPSHOT_ENV}=0 to override)"
            )

        if error is not None and feedback is not None:
            logger.warning(
                "SOC: discarding the measured vector of a failed round: rs_exe=%s rs_attack=%s "
                "rs_service=%s F_i=%s",
                feedback["rs_exe"],
                feedback["rs_attack"],
                feedback["rs_service"],
                feedback["F_i"],
            )

        attack_error = attack_result.get("attack_error")

        if error is not None:
            return self.build_failure(
                attack_mode=attack_mode,
                error=error,
                elapsed_s=elapsed,
                status=200,
                measured_attack=score,
                attack_error=attack_error,
            )

        if feedback is None:  # defensive: cannot happen, but never invent a vector
            return self.build_failure(
                attack_mode=attack_mode,
                error="no feedback vector was produced",
                elapsed_s=elapsed,
                status=200,
                measured_attack=score,
                attack_error=attack_error,
            )

        body = {
            "success": True,
            "score": round(score, 6),
            "feedback": feedback,
            "attack_mode": attack_mode,
            "elapsed_s": round(elapsed, 3),
            "error": None,
            # Additive (docs/INTERFACES.md §3.1 does not define it): the attack
            # script's own message when the attack could not progress -- e.g.
            # "oracle not confirmed" after a successful block_ip.  The round is
            # still a measurement (rs_attack 0.0); this only says why.
            "attack_error": attack_error,
            # Additive, and the whole point of `abort_kind`: it is the
            # producer's own classification and `caused_by_defence` is the verdict of the
            # pre-attack control.  Kept in the response so an evidence file records *why*
            # a round is all-false instead of leaving a reader to guess (INTERFACES §2.1).
            "abort_kind": attack_result.get("abort_kind"),
            "attack_unreached": bool(attack_result.get("attack_unreached")),
            "caused_by_defence": attack_result.get("caused_by_defence"),
        }
        logger.info(
            "SOC: round on %s done in %.1fs: rs_exe=%.4f rs_attack=%.4f rs_service=%d F_i=%.4f%s%s",
            pair.name,
            elapsed,
            feedback["rs_exe"],
            feedback["rs_attack"],
            feedback["rs_service"],
            feedback["F_i"],
            f" attack_error={attack_error!r}" if attack_error else "",
            f" abort_kind={body['abort_kind']!r} caused_by_defence={body['caused_by_defence']!r}"
            if body["attack_unreached"]
            else "",
        )
        return body, 200

    # --------------------------------------------------------------- bodies

    @staticmethod
    def build_failure(
        *,
        attack_mode: str,
        error: str,
        elapsed_s: float,
        status: int,
        measured_attack: float = 0.0,
        attack_error: str | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Uniform failure document (``success: false``, ``feedback: null``)."""
        return (
            {
                "success": False,
                "score": round(float(measured_attack), 6),
                "feedback": None,
                "attack_mode": attack_mode,
                "elapsed_s": round(elapsed_s, 3),
                "error": error,
                "attack_error": attack_error,
            },
            status,
        )
