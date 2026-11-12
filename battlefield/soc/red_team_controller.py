# SPDX-License-Identifier: Apache-2.0
"""Red Team Controller (RTC) for SecLoop -- paper Section II-B-3, Eq. (9).

    E_RVM = RTC(S_k)

The RTC launches the predefined attack sequence on the red-team VM and reports
**stage-level** results, which become ``rs_attack`` (Eq. 11) further down the
pipeline.

Contract with the attack script (docs/INTERFACES.md §2.1, §2.3)
-------------------------------------------------------------
The script prints **exactly one** machine-readable line to stdout::

    [RESULT] {"attack_mode":"sqli", ..., "score":0.4, "stages":[{"name":...,"success":true,"weight":0.1}, ...], "error":null}

* the prefix is exactly ``[RESULT] `` (one space) and the remainder is one line
  of valid JSON;
* ``stages`` is the fixed five-entry SQLi list with weights ``0.1/0.1/0.2/0.2/0.4``;
* human-readable progress goes to stderr, so stdout is never filtered or guessed;
* ``error`` is non-null when the script itself could not carry the attack out.

What this parser refuses
------------------------
* Human-readable score regexes (a capital-S marker with
  whitespace, and the lowercase variant).  There is one contract, JSON,
  and no text fallback.
* Turning *any non-empty stdout* into a single
  successful stage, which would make a failed attack look like a successful one.  Here the
  stage flags only ever come from a strictly parsed ``[RESULT]`` payload.

Measured vs unmeasured (why this distinction is the whole point)
---------------------------------------------------------------
``parse_attack_result()`` failing, a missing ``[RESULT]`` line, an empty stage
list or a killed run means **there is no measurement**: ``success: False``,
``stages == []``, ``score == 0.0``, ``error`` set, plus a ``WARNING``.  Nothing is
invented.

A **valid** line, in contrast, is always a measurement, even when the script sets
its own ``error``.  The probe reports ``error`` for "the attack could not carry
itself out" -- packets dropped by ``block_ip``, an unconfirmed time oracle, an
unreachable target -- and every one of those is a legitimate Eq. 11 reading of
``0.0`` (the attack did not succeed).  Marking them unmeasurable would make a
*working* defence invisible to the loop: after ``block_ip`` the SOC must report
``rs_attack -> 0.0`` while ``rs_service`` stays ``1``.
The script's own message is preserved in ``attack_error`` and logged, and
``rs_service`` is what separates "the attack was blocked" from "the target is
gone" (``rs_service = 0``).
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .policy_execution_validator import ABORT_KINDS, TARGET_UNREACHABLE, coerce_success_flag
from .vagrant_driver import VagrantDriver

logger = logging.getLogger(__name__)

__all__ = ["ATTACK_COMMANDS_PATH", "AttackResultError", "RedTeamController", "parse_attack_result"]

#: Exact stdout prefix of the single machine-readable result line.
RESULT_PREFIX = "[RESULT] "

#: ``<repo>/SecLoop/battlefield/soc/attack_commands.json``
ATTACK_COMMANDS_PATH = Path(__file__).resolve().parent / "attack_commands.json"

ATTACK_COMMANDS_ENV = "SOC_ATTACK_COMMANDS"
ATTACK_TIMEOUT_ENV = "SOC_ATTACK_TIMEOUT_S"
ATTACK_DELAY_ENV = "SOC_ATTACK_DELAY_S"
DEFAULT_ATTACK_TIMEOUT_S = 900.0
DEFAULT_TARGET_IP = "192.168.57.200"
MAX_LOGGED_OUTPUT_CHARS = 20000


class AttackResultError(ValueError):
    """Raised when the attack stdout does not carry a usable ``[RESULT]`` payload."""


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


def parse_attack_result(output: str) -> dict[str, Any]:
    """Parse the single ``[RESULT] {json}`` line out of attack stdout.

    Args:
        output: raw stdout of the attack script (stderr must not be mixed in).

    Returns:
        ``{"attack_mode", "target_ip", "score", "stages", "error", "abort_kind", "payload"}``
        where ``stages`` is ``[{name, success, weight}, ...]`` in script order and
        ``abort_kind`` is ``None`` for a completed run or one of the ``INTERFACES`` §2.1
        kinds otherwise (``target-unreachable`` is the one a successful block produces).

    Raises:
        AttackResultError: no ``[RESULT] `` line, invalid JSON, or a payload whose
            structure violates docs/INTERFACES.md §2.1.  Callers must translate
            that into ``rs_attack = 0.0`` plus a WARNING -- never into a
            fabricated successful stage.
    """
    if not output or not output.strip():
        raise AttackResultError("attack produced no stdout at all")

    payload_text: str | None = None
    hits = 0
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith(RESULT_PREFIX):
            continue
        hits += 1
        payload_text = line[len(RESULT_PREFIX):]
    if payload_text is None:
        raise AttackResultError(
            f"no {RESULT_PREFIX!r} line in attack stdout "
            f"({len(output.splitlines())} lines inspected)"
        )
    if hits > 1:
        logger.warning(
            "RTC: attack printed %d %r lines; using the last one (contract says exactly one)",
            hits,
            RESULT_PREFIX.strip(),
        )

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        raise AttackResultError(f"{RESULT_PREFIX.strip()} payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise AttackResultError(
            f"{RESULT_PREFIX.strip()} payload must be a JSON object, got {type(payload).__name__}"
        )

    raw_stages = payload.get("stages")
    if raw_stages is None:
        raise AttackResultError("attack payload has no 'stages' key")
    if isinstance(raw_stages, (str, bytes)) or not isinstance(raw_stages, Sequence):
        raise AttackResultError(
            f"attack payload 'stages' must be a list, got {type(raw_stages).__name__}"
        )

    stages: list[dict[str, Any]] = []
    for index, raw_stage in enumerate(raw_stages):
        if not isinstance(raw_stage, Mapping):
            raise AttackResultError(
                f"attack payload stages[{index}] is not an object "
                f"(got {type(raw_stage).__name__})"
            )
        name = raw_stage.get("name")
        if not isinstance(name, str) or not name.strip():
            raise AttackResultError(f"attack payload stages[{index}] has no usable 'name'")
        if "success" not in raw_stage:
            raise AttackResultError(f"attack payload stages[{index}] has no 'success' flag")
        stage: dict[str, Any] = {
            "name": name.strip(),
            "success": coerce_success_flag(
                raw_stage.get("success"), field=f"stages[{index}].success"
            ),
        }
        weight = _as_float(raw_stage.get("weight"))
        if weight is not None:
            stage["weight"] = weight
        stages.append(stage)

    score = _as_float(payload.get("score"))
    if score is None:
        if stages and all("weight" in stage for stage in stages):
            score = round(
                sum(float(stage["weight"]) * (1.0 if stage["success"] else 0.0) for stage in stages),
                6,
            )
            logger.warning(
                "RTC: attack payload had no numeric 'score'; recomputed Sigma(weight*success)=%.6f "
                "from the reported stages",
                score,
            )
        else:
            score = 0.0
            logger.warning("RTC: attack payload had no numeric 'score'; using 0.0")
    elif not 0.0 <= score <= 1.0:
        logger.warning("RTC: attack reported out-of-range score %r; clamping for reporting", score)
        score = min(max(score, 0.0), 1.0)

    error = payload.get("error")
    error = None if error is None else str(error)

    attack_mode = payload.get("attack_mode")
    target_ip = payload.get("target_ip")
    abort_kind = payload.get("abort_kind")
    abort_kind = None if abort_kind is None else str(abort_kind)
    if abort_kind is not None and abort_kind not in ABORT_KINDS:
        # An unknown class must never be read as "the defence worked" (INTERFACES 2.1).
        logger.warning(
            "RTC: attack reported abort_kind %r, which is not in the contract; treating it "
            "as 'unclassified' (unmeasured)",
            abort_kind,
        )
        abort_kind = "unclassified"
    return {
        "attack_mode": str(attack_mode) if attack_mode is not None else None,
        "target_ip": str(target_ip) if target_ip is not None else None,
        "score": round(float(score), 6),
        "stages": stages,
        "error": error,
        "abort_kind": abort_kind,
        "payload": dict(payload),
    }


class RedTeamController:
    """Runs the registered attack script on a red-team VM via Vagrant SSH.

    Args:
        driver: optional :class:`~soc.vagrant_driver.VagrantDriver` (dependency
            injection: tests pass a fake, production passes nothing).
        vagrant_root: Vagrant root directory; defaults to ``SOAR_VAGRANT_ROOT``
            or ``<repo>/SecLoop/vagrant``.
        attack_commands_path: registry JSON; defaults to ``soc/attack_commands.json``
            (override with ``SOC_ATTACK_COMMANDS``).
        default_target_ip: target used when the caller does not pass one.
        attack_timeout_s: guest-side budget for one attack run
            (``SOC_ATTACK_TIMEOUT_S``, default 900 s).
    """

    def __init__(
        self,
        driver: VagrantDriver | None = None,
        *,
        vagrant_root: str | os.PathLike[str] | None = None,
        attack_commands_path: str | os.PathLike[str] | None = None,
        default_target_ip: str = DEFAULT_TARGET_IP,
        attack_timeout_s: float | None = None,
    ) -> None:
        self.driver = driver or VagrantDriver(root=vagrant_root)
        self.default_target_ip = default_target_ip
        self.attack_timeout_s = float(
            attack_timeout_s
            if attack_timeout_s is not None
            else os.getenv(ATTACK_TIMEOUT_ENV, DEFAULT_ATTACK_TIMEOUT_S)
        )
        path = Path(
            attack_commands_path
            or os.getenv(ATTACK_COMMANDS_ENV)
            or ATTACK_COMMANDS_PATH
        ).expanduser()
        self.attack_commands_path = path
        self._registry = self._load_registry(path)

    # ------------------------------------------------------------- registry

    @staticmethod
    def _load_registry(path: Path) -> dict[str, dict[str, Any]]:
        """Load and validate the attack-command registry (fail loudly)."""
        try:
            with path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except OSError as exc:
            raise RuntimeError(f"cannot read the attack registry at {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"attack registry {path} is not valid JSON: {exc}") from exc

        if not isinstance(raw, Mapping) or not raw:
            raise RuntimeError(f"attack registry {path} must be a non-empty JSON object")

        registry: dict[str, dict[str, Any]] = {}
        for mode, entry in raw.items():
            if str(mode).startswith("_"):
                continue  # documented comment key inside the JSON registry
            if isinstance(entry, str):  # tolerate a legacy string form
                logger.warning(
                    "RTC: registry entry %r uses the legacy string form; wrapping it", mode
                )
                entry = {"command": entry}
            if not isinstance(entry, Mapping) or not entry.get("command"):
                raise RuntimeError(
                    f"attack registry entry {mode!r} in {path} must be an object with a 'command'"
                )
            registry[str(mode)] = dict(entry)
        logger.debug("RTC: loaded %d attack mode(s) from %s", len(registry), path)
        return registry

    @property
    def attack_modes(self) -> list[str]:
        """Registered attack modes, sorted (used by ``GET /health``)."""
        return sorted(self._registry)

    @property
    def registry(self) -> dict[str, dict[str, Any]]:
        """Read-only view of the loaded registry (diagnostics/tests)."""
        return {mode: dict(entry) for mode, entry in self._registry.items()}

    # --------------------------------------------------------------- attack

    def build_command(self, attack_mode: str, target_ip: str | None = None) -> str:
        """Render the full guest-side shell command for ``attack_mode``.

        The registry owns the semantic command; the RTC owns the working
        directory and the hard ``timeout`` wrapper, so a stuck attack can never
        wedge the SOC (the guest-side timeout exits 124 and, per the attack
        contract, no ``[RESULT]`` line is printed -- which becomes
        ``rs_attack = 0.0`` plus a WARNING rather than a fake success).

        Raises:
            KeyError: unknown attack mode.
            ValueError: the rendered command is not a usable shell command.
        """
        entry = self._registry[attack_mode]
        command = str(entry["command"])
        params = {
            "target_ip": target_ip or entry.get("default_target_ip") or self.default_target_ip,
            "red_vm": entry.get("red_vm", ""),
            "blue_vm": entry.get("blue_vm", ""),
            "delay_s": entry.get("delay_s", os.getenv(ATTACK_DELAY_ENV, 1)),
            "request_timeout_s": entry.get("request_timeout_s", 8),
        }
        try:
            rendered = command.format(**params)
        except (KeyError, IndexError) as exc:
            raise ValueError(
                f"attack registry command for {attack_mode!r} references an unknown "
                f"placeholder: {exc}"
            ) from exc
        if not rendered.strip():
            raise ValueError(f"attack registry command for {attack_mode!r} rendered empty")

        workdir = str(entry.get("workdir", "~/attacks")).rstrip("/")
        prefix = f"cd {workdir} && " if workdir else ""
        return (
            f"{prefix}timeout --signal=TERM --kill-after=15 "
            f"{self.attack_timeout_s:.0f} {rendered}"
        )

    def run_attack(
        self,
        attack_mode: str = "sqli",
        red_vm: str = "kali",
        target_ip: str | None = None,
        timeout_s: float | None = None,
    ) -> dict[str, Any]:
        """Launch one attack run and strictly parse its ``[RESULT]`` line.

        Returns:
            ``{success, parsed, attack_mode, vm, target_ip, command, output,
            stages, score, error, attack_error, exit_code, elapsed_s,
            contract_warnings}``.

            Two levels of failure, kept apart on purpose:

            * ``success`` means **the attack was measured**: a valid ``[RESULT]``
              line was parsed and it carries a non-empty stage list.  The stage
              flags are then taken verbatim, so an attack that never landed
              (blocked packets, unconfirmed time oracle) is a legitimate
              measurement whose ``rs_attack`` is ``0.0`` -- which is what Eq. 11
              says and what a *working* defence has to look like in the loop
              (``docs/INTERFACES.md`` §4, paper Eq. 11).
            * ``error`` is set only when there is **no measurement at all** (no
              line, unparsable payload, empty stage list, timeout/watchdog) --
              i.e. ``rs_attack`` would be an artefact rather than a reading.
            * ``attack_error`` carries the script's own ``error`` field whenever
              it reported one ("oracle not confirmed", "target unreachable", ...).
              It is informational: the caller sees *why* the attack did not
              progress, while ``rs_service`` tells it whether the service was
              lost (attack blocked) or the target is simply gone.
        """
        entry = self._registry.get(attack_mode)
        if entry is None:
            message = (
                f"unknown attack mode {attack_mode!r}; registered modes: "
                f"{', '.join(self.attack_modes) or 'none'}"
            )
            logger.error("RTC: %s", message)
            return self._empty_result(attack_mode, red_vm, target_ip, None, message, None, 0.0, False)

        try:
            command = self.build_command(attack_mode, target_ip)
        except ValueError as exc:
            logger.error("RTC: %s", exc)
            return self._empty_result(attack_mode, red_vm, target_ip, None, str(exc), None, 0.0, False)

        budget = float(timeout_s if timeout_s is not None else self.attack_timeout_s)
        logger.info("RTC: launching %r on %s: %s", attack_mode, red_vm, command)
        started = time.monotonic()
        ssh = self.driver.ssh(red_vm, command, timeout_s=budget)
        elapsed = round(time.monotonic() - started, 3)
        output = ssh.stdout or ""

        if ssh.timed_out:
            message = (
                f"attack exceeded {budget:.0f}s host watchdog on {red_vm}"
                f"{f': {ssh.error}' if ssh.error else ''}"
            )
        elif ssh.returncode == 124:
            message = f"attack hit the guest-side timeout of {self.attack_timeout_s:.0f}s"
        elif ssh.returncode != 0:
            message = f"vagrant ssh exited {ssh.returncode} on {red_vm}: {ssh.error or 'no detail'}"
        else:
            message = None

        parsed_payload: dict[str, Any] | None = None
        parse_error: str | None = None
        if output.strip():
            try:
                parsed_payload = parse_attack_result(output)
            except AttackResultError as exc:
                parse_error = str(exc)
        else:
            parse_error = message or "attack produced no stdout"

        # The producer contract is "write the [RESULT] line last, then exit 0", so a
        # non-zero exit alongside a valid line means the transport is lying about
        # the exit status (Vagrant/VMware can do that).  The contract line wins,
        # but the contradiction is reported.
        if parsed_payload is not None and message:
            if ssh.timed_out or ssh.returncode == 124:
                logger.warning(
                    "RTC: %s on %s; a %s line was parsed but a killed run is never trusted",
                    message,
                    red_vm,
                    RESULT_PREFIX.strip(),
                )
                parsed_payload = None  # a killed run cannot be trusted
                parse_error = message
            else:
                logger.warning(
                    "RTC: %s on %s, yet a valid %s line was parsed; trusting the line "
                    "(the producer writes it last and exits 0)",
                    message,
                    red_vm,
                    RESULT_PREFIX.strip(),
                )

        if parsed_payload is None:
            detail = parse_error or "unparsable attack output"
            logger.warning(
                "RTC: attack %r on %s produced no usable %s payload (%s); "
                "this round has NO measurement -- an unmeasured attack must not look defended",
                attack_mode,
                red_vm,
                RESULT_PREFIX.strip(),
                detail,
            )
            return self._empty_result(
                attack_mode, red_vm, target_ip, command, detail, ssh.returncode, elapsed, False, output
            )

        stages = parsed_payload["stages"]
        attack_error = parsed_payload["error"]
        abort_kind = parsed_payload.get("abort_kind")

        if abort_kind is not None and abort_kind != TARGET_UNREACHABLE:
            # The producer said *why* it stopped, and it was not "the target was out of
            # reach" (INTERFACES §2.1). That is not a verdict on the defence: an
            # unconfirmed oracle or a broken dependency produces the very same all-false
            # stage list a perfect block produces, so this round has NO measurement and
            # must not be credited. (`unclassified` lands here by construction.)
            detail = (
                f"attack aborted with abort_kind={abort_kind!r}: the harness could not "
                f"measure the target, so this round carries no verdict on the defence "
                f"({attack_error or 'no detail'})"
            )
            logger.warning("RTC: %s on %s; this round has NO measurement", detail, red_vm)
            return self._empty_result(
                attack_mode,
                red_vm,
                target_ip,
                command,
                detail,
                ssh.returncode,
                elapsed,
                True,
                output,
                attack_error=attack_error,
            )

        attack_unreached = abort_kind == TARGET_UNREACHABLE
        if attack_unreached:
            # "The attack never got to run" **counts as blocked** (INTERFACES §2.1):
            # check_health failed with a connect/timeout error or a health anchor that did
            # not answer 200 with the contract marker, which is what a DROP rule looks
            # like from the attacker's side. `rs_attack` therefore stays 0.0 -- computed
            # from the reported stages, never fabricated.
            #
            # Whether the defence *caused* it is a separate, causal question: only a
            # pre-attack control can answer it, so it starts as `None` =
            # "unproven" and the pipeline upgrades or vetoes it.
            logger.warning(
                "RTC: attack on %s reports abort_kind=%r (%r): the reported %d stage(s) are "
                "taken verbatim -> rs_attack will be %.4f. Causation is NOT proven here; "
                "enable pre_attack_sample for the control (INTERFACES §2.2)",
                red_vm,
                abort_kind,
                attack_error,
                len(stages),
                sum(1 for s in stages if s["success"]) / len(stages) if stages else 0.0,
            )

        if not stages:
            detail = "attack reported an empty stage list (nothing was measured)"
            logger.warning("RTC: %s on %s; this round has NO measurement", detail, red_vm)
            return self._empty_result(
                attack_mode,
                red_vm,
                target_ip,
                command,
                detail,
                ssh.returncode,
                elapsed,
                True,
                output,
                attack_error=attack_error,
            )

        contract_warnings = self._check_contract(attack_mode, stages)
        if attack_error:
            # A valid line whose stages are all false after a deployed defence is a
            # *measurement* (rs_attack 0.0), not a broken round: that is exactly what
            # "block_ip worked" has to look like (paper Eq. 11).
            logger.warning(
                "RTC: attack script reports it could not carry the attack out on %s (%r); "
                "the %d reported stage(s) are taken verbatim -- rs_attack will be %.4f, and "
                "rs_service distinguishes 'service lost' from 'attack blocked'",
                red_vm,
                attack_error,
                len(stages),
                sum(1 for s in stages if s["success"]) / len(stages),
            )

        result = {
            "success": True,
            "parsed": True,
            "attack_mode": attack_mode,
            "vm": red_vm,
            "target_ip": target_ip or self._registry[attack_mode].get("default_target_ip", self.default_target_ip),
            "command": command,
            "output": self._trim(output),
            "stages": stages,
            "score": parsed_payload["score"],
            "error": None,
            "attack_error": attack_error,
            "abort_kind": abort_kind,
            "attack_unreached": attack_unreached,
            # Provenance, not opinion: `None` = nobody checked whether the defence caused
            # the unreachability. Only the pipeline, which owns the pre-attack control,
            # may set True/False (INTERFACES §2.2).
            "caused_by_defence": None,
            "exit_code": ssh.returncode,
            "elapsed_s": elapsed,
            "contract_warnings": contract_warnings,
        }
        logger.info(
            "RTC: attack %r on %s finished in %.1fs (exit=%s): score=%.4f stages=%s%s%s",
            attack_mode,
            red_vm,
            elapsed,
            ssh.returncode,
            result["score"],
            ",".join(f"{s['name']}={'1' if s['success'] else '0'}" for s in stages),
            f" attack_error={attack_error!r}" if attack_error else "",
            f" abort_kind={abort_kind!r}" if abort_kind else "",
        )
        return result

    # -------------------------------------------------------------- helpers

    def _check_contract(self, attack_mode: str, stages: Sequence[Mapping[str, Any]]) -> list[str]:
        """Compare reported stages with the registry metadata (warn, never rewrite)."""
        expected = self._registry[attack_mode].get("stages")
        if not isinstance(expected, Sequence) or isinstance(expected, (str, bytes)) or not expected:
            return []
        warnings: list[str] = []
        expected_names = [
            str(item.get("name"))
            for item in expected
            if isinstance(item, Mapping) and item.get("name")
        ]
        reported_names = [str(stage["name"]) for stage in stages]
        if expected_names and reported_names != expected_names:
            warnings.append(
                f"stage names/order differ from the registry: reported {reported_names}, "
                f"expected {expected_names}"
            )
        expected_weights = {
            str(item.get("name")): _as_float(item.get("weight"))
            for item in expected
            if isinstance(item, Mapping) and item.get("name")
        }
        weight_sum = 0.0
        for stage in stages:
            weight = stage.get("weight")
            if weight is None:
                continue
            weight_sum += float(weight)
            wanted = expected_weights.get(str(stage["name"]))
            if wanted is not None and abs(float(weight) - wanted) > 1e-6:
                warnings.append(
                    f"stage {stage['name']!r} weight {weight} != registry weight {wanted}"
                )
        if weight_sum and abs(weight_sum - 1.0) > 1e-3:
            warnings.append(f"stage weights sum to {weight_sum:.4f}, not 1.0")
        if warnings:
            logger.warning(
                "RTC: attack %r violates the [RESULT] contract in %d way(s): %s",
                attack_mode,
                len(warnings),
                "; ".join(warnings),
            )
        return warnings

    @staticmethod
    def _trim(output: str) -> str:
        if len(output) <= MAX_LOGGED_OUTPUT_CHARS:
            return output
        return output[:MAX_LOGGED_OUTPUT_CHARS] + "... [truncated]"

    @staticmethod
    def _empty_result(
        attack_mode: str,
        red_vm: str,
        target_ip: str | None,
        command: str | None,
        error: str,
        exit_code: int | None,
        elapsed_s: float,
        parsed: bool,
        output: str = "",
        attack_error: str | None = None,
    ) -> dict[str, Any]:
        """An explicitly *unmeasured* attack result (there is no usable stage list)."""
        return {
            "success": False,
            "parsed": parsed,
            "attack_mode": attack_mode,
            "vm": red_vm,
            "target_ip": target_ip,
            "command": command,
            "output": RedTeamController._trim(output),
            "stages": [],
            "score": 0.0,
            "error": error,
            "attack_error": attack_error,
            "exit_code": exit_code,
            "elapsed_s": elapsed_s,
            "contract_warnings": [],
        }
