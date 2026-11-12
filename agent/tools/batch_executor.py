# SPDX-License-Identifier: Apache-2.0
"""SOC transport for the SecLoop agent — **one request per strategy**.

This module owns the only HTTP code path that talks to the blue-team SOC
(``POST /execute_ability``, INTERFACES §3).  The whole strategy is submitted in a single
request and the SOC answers with the complete 3-D feedback vector
(``rs_exe`` / ``rs_attack`` / ``rs_service``) plus ``F_i``; the client relays that vector
verbatim and never recomputes the metrics (PEV is the SOC's job, INTERFACES §4.5).

A strategy is deployed as one round trip: the request carries every tool, so the
combination is evaluated as one defence rather than as independent red/blue rounds.

The dataset path is resolved in :func:`_dataset_path`.  A
``Path(__file__).resolve().parents[n]`` offset that is one level short resolves to a
non-existent file, and the tempting fallback -- hard-coded VM names inside a bare
``except: pass`` -- is refused: the offset is derived once from :data:`REPO_ROOT`, and any
unresolved dataset raises :class:`DatasetPathError` with the list of searched locations.

Endpoint: ``SOAR_ABILITY_ENDPOINT``, default ``http://127.0.0.1:8988/execute_ability``
(INTERFACES §1).  Round timeout: ``SOAR_ROUND_TIMEOUT_S``, default
:data:`DEFAULT_ROUND_TIMEOUT_S` -- a round runs a whole attack, so this must outlive the
SOC's own ``SOC_ATTACK_TIMEOUT_S`` budget.  VM names / attack mode: explicit env vars,
else the dataset record, else the INTERFACES §1 constants with a WARNING naming the
source.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)

#: INTERFACES §1 — the single supported SOC endpoint.
DEFAULT_SOC_ENDPOINT = "http://127.0.0.1:8988/execute_ability"

#: Environment variable that overrides the SOC endpoint.
SOC_ENDPOINT_ENV = "SOAR_ABILITY_ENDPOINT"

#: Environment variable that overrides the per-round SOC read timeout, in seconds.
ROUND_TIMEOUT_ENV = "SOAR_ROUND_TIMEOUT_S"

#: The SOC's own phase budgets, mirrored here so the round budget below is a
#: *derivation* rather than a guess.  ``tests/test_agent_soc_round_timeout.py``
#: re-reads the real values out of the SOC sources and fails if any of them grows
#: past what this file allows for, so the two subsystems cannot drift apart.
SOC_POOL_ACQUIRE_S = 300.0       # vm_pool.DEFAULT_POOL_TIMEOUT_S
SOC_ATTACK_BUDGET_S = 900.0      # red_team_controller.DEFAULT_ATTACK_TIMEOUT_S
SOC_SSH_GRACE_S = 120.0          # vagrant_driver.SSH_WATCHDOG_GRACE_S
SOC_SNAPSHOT_WATCHDOG_S = 900.0  # vagrant_driver.SNAPSHOT_WATCHDOG_S
SOC_SSH_STEP_S = 120.0           # vagrant_driver.DEFAULT_SSH_TIMEOUT_S
#: Non-attack SSH steps a round performs (pre-attack sample, strategy deployment).
SOC_OTHER_STEPS = 2

#: A round is not a quick RPC: the SOC waits for a free VM pair, deploys the strategy,
#: runs a **whole attack**, and rolls the blue VM back.  A client that gives up before
#: the SOC's own budgets expire can never observe a real full-length round: a 120 s default
#: times out against real hardware while looking perfectly fine against a stubbed, fast SOC.
#:
#: Worst case, from the SOC's own budgets:
#:
#:   pool acquire        300      vm_pool.DEFAULT_POOL_TIMEOUT_S
#:   attack + grace      900+120  red_team_controller + vagrant_driver grace
#:   snapshot rollback  1800      BTC.restore_snapshot -> snapshot_list + snapshot_restore,
#:                                each bounded by SNAPSHOT_WATCHDOG_S (900) *separately*;
#:                                a round performs exactly one rollback
#:   other SSH steps     480      2 x (DEFAULT_SSH_TIMEOUT_S + grace)
#:   --------------------------------------------------------------
#:   total              3600
#:
#: This is a safety bound, not an expected duration: measured full-length rounds ran
#: 212.9 s (undefended) and 126.5 s (blocked) on the lab host -- see
#: the feedback vector.  Override per deployment with
#: ``SOAR_ROUND_TIMEOUT_S``.
DEFAULT_ROUND_TIMEOUT_S = (
    SOC_POOL_ACQUIRE_S
    + SOC_ATTACK_BUDGET_S
    + SOC_SSH_GRACE_S
    + 2 * SOC_SNAPSHOT_WATCHDOG_S
    + SOC_OTHER_STEPS * (SOC_SSH_STEP_S + SOC_SSH_GRACE_S)
)

#: Environment variable that points directly at a ``security_dataset.json``.
DATASET_PATH_ENV = "SOAR_DATASET"

#: Environment variables that pin the VM pair explicitly.
RED_VM_ENV = "SOAR_RED_VM"
BLUE_VM_ENV = "SOAR_BLUE_VM"
ATTACK_MODE_ENV = "SOAR_ATTACK_MODE"

#: INTERFACES §1 constants (red team machine, blue team machine, attack mode).
DEFAULT_RED_VM = "kali"
DEFAULT_BLUE_VM = "target"
DEFAULT_ATTACK_MODE = "sqli"
SUPPORTED_ATTACK_MODES = ("sqli",)

#: ``agent/tools/batch_executor.py`` -> ``parents[2]`` is the ``SecLoop`` repository root.
#: (``parents[1]`` points inside ``agent/``; the index must be one higher.)
REPO_ROOT = Path(__file__).resolve().parents[2]

#: Locations searched for the alert/VM dataset when ``SOAR_DATASET`` is not set.
DATASET_CANDIDATES = (
    "dataset/security_dataset.json",
    "training/dataset/security_dataset.json",
    "ids/security_dataset.json",
    "ids/dataset/security_dataset.json",
    "data/security_dataset.json",
)

#: Retry budget for capacity exhaustion (INTERFACES §3.1: ``429`` is retryable).
RETRY_ATTEMPTS_ENV = "SECLOOP_RETRY_ATTEMPTS"
#: Ceiling for one backoff sleep, so a hostile ``Retry-After`` cannot stall training.
RETRY_MAX_SLEEP_ENV = "SECLOOP_RETRY_MAX_SLEEP_S"
#: Per-sample policy for a retryable failure that survived the budget:
#: ``exclude`` (default) drops the sample from the update; ``zero`` scores it
#: ``R_exec = R_eva = 0.0``.
RETRYABLE_POLICY_ENV = "SECLOOP_RETRYABLE_POLICY"


class SOCError(RuntimeError):
    """Base class for SOC transport failures."""


class SOCUnavailableError(SOCError):
    """The SOC endpoint could not be reached or answered with a transport-level error."""


class SOCBusyError(SOCUnavailableError):
    """Capacity was exhausted (HTTP ``429``) for the whole retry budget.

    **Retryable, and not a statement about the strategy.** ``INTERFACES.md`` §3.1 requires
    a client to tell this apart from ``200 + success:false``: the first says "try again
    later", the second says "this strategy did not work". Subclassing
    :class:`SOCUnavailableError` keeps existing handlers working, while the distinct type
    lets the reward layer **exclude** the sample instead of scoring it ``0.0``.
    """


def parse_retry_after(value: Any, *, now: datetime | None = None) -> float | None:
    """Seconds to wait from a ``Retry-After`` header, or ``None`` if unusable.

    RFC 9110 allows either delta-seconds or an HTTP-date. Both are accepted because a
    server may send either; anything unparsable or in the past returns ``None`` so the
    caller falls back to its own exponential backoff instead of guessing.

    Pure function (``now`` is injectable) so it is testable without a network.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        seconds = float(text)
    except ValueError:
        pass
    else:
        return max(0.0, seconds)

    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return max(0.0, (when - reference).total_seconds())


def retryable_policy() -> str:
    """How to treat a retryable failure that outlived the retry budget.

    ``exclude`` (the default): a busy VM pool is our
    problem, not the policy's, so the sample is dropped from the update. ``zero``
    scores it ``R_exec = R_eva = 0.0``.
    """
    value = (os.getenv(RETRYABLE_POLICY_ENV) or "exclude").strip().lower()
    return value if value in {"exclude", "zero"} else "exclude"


class DatasetPathError(RuntimeError):
    """The dataset file could not be resolved (never silently substituted)."""


class DatasetConfigError(DatasetPathError):
    """The dataset was found but does not carry the VM configuration it must carry."""


@dataclass(frozen=True)
class VMConfig:
    """VM pair and attack mode for an ``/execute_ability`` request."""

    red_vm: str
    blue_vm: str
    attack_mode: str
    source: str
    dataset_path: Path | None = None

    def as_request_fields(self) -> dict[str, str]:
        """Return the three request fields of INTERFACES §3.1."""
        return {
            "attack_mode": self.attack_mode,
            "red_vm": self.red_vm,
            "blue_vm": self.blue_vm,
        }


# --------------------------------------------------------------------------------------
# Dataset / VM configuration
# --------------------------------------------------------------------------------------
def _dataset_path() -> Path:
    """Resolve ``security_dataset.json`` — raising when it cannot be found.

    Resolution order:
      1. ``SOAR_DATASET`` (explicit file, or a directory containing the file);
      2. :data:`DATASET_CANDIDATES` relative to :data:`REPO_ROOT`.

    Raises:
        DatasetPathError: nothing was found, with the searched locations in the message.
            A wrong path would let the caller fall back to hard-coded VM names; this
            raises instead of silently doing that.
    """
    override = (os.environ.get(DATASET_PATH_ENV) or "").strip()
    if override:
        candidate = Path(override)
        if candidate.is_dir():
            candidate = candidate / "security_dataset.json"
        if not candidate.is_file():
            raise DatasetPathError(
                f"{DATASET_PATH_ENV}={override!r} does not point at a security_dataset.json "
                f"(checked {candidate})"
            )
        logger.debug("dataset resolved from %s: %s", DATASET_PATH_ENV, candidate)
        return candidate

    searched: list[Path] = []
    for relative in DATASET_CANDIDATES:
        candidate = REPO_ROOT / relative
        searched.append(candidate)
        if candidate.is_file():
            logger.debug("dataset resolved: %s", candidate)
            return candidate

    listing = "\n  ".join(str(path) for path in searched)
    raise DatasetPathError(
        f"security_dataset.json not found relative to the repository root {REPO_ROOT}; "
        f"searched:\n  {listing}\n"
        f"Set {DATASET_PATH_ENV} to the dataset file, or {RED_VM_ENV}/{BLUE_VM_ENV}/"
        f"{ATTACK_MODE_ENV} to pin the VM pair explicitly."
    )


#: Public alias of the helper name checked in INTERFACES §12.
resolve_dataset_path = _dataset_path


def _read_dataset_records(path: Path) -> list[Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DatasetConfigError(f"cannot read dataset {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DatasetConfigError(f"dataset {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise DatasetConfigError(f"dataset {path} must be a non-empty JSON array of records")
    return data


def read_vm_config() -> VMConfig:
    """Return the VM pair / attack mode for an ``/execute_ability`` request.

    Resolution order (each step is logged, so the origin is never a mystery):
      1. ``SOAR_RED_VM`` / ``SOAR_BLUE_VM`` / ``SOAR_ATTACK_MODE`` (explicit operator pin);
      2. the first record of the dataset (``red_vm_name`` / ``blue_vm_name`` /
         ``attack_mode``) — a record missing those keys raises
         :class:`DatasetConfigError` instead of guessing;
      3. no dataset anywhere: WARNING + the INTERFACES §1 constants, naming the source.

    Raises:
        DatasetConfigError: a dataset was found but is unusable.
    """
    env_red = (os.environ.get(RED_VM_ENV) or "").strip()
    env_blue = (os.environ.get(BLUE_VM_ENV) or "").strip()
    env_mode = (os.environ.get(ATTACK_MODE_ENV) or "").strip()
    if env_red or env_blue or env_mode:
        config = VMConfig(
            red_vm=env_red or DEFAULT_RED_VM,
            blue_vm=env_blue or DEFAULT_BLUE_VM,
            attack_mode=env_mode or DEFAULT_ATTACK_MODE,
            source=(
                f"env:{RED_VM_ENV}/{BLUE_VM_ENV}/{ATTACK_MODE_ENV}"
                if env_red and env_blue and env_mode
                else f"env(partial):{RED_VM_ENV}/{BLUE_VM_ENV}/{ATTACK_MODE_ENV}+INTERFACES §1 defaults"
            ),
        )
        logger.info("VM config from environment: %s", config)
        return _warn_on_contract_mismatch(config)

    try:
        dataset = _dataset_path()
    except DatasetPathError as exc:
        logger.warning(
            "no VM dataset available (%s); falling back to the INTERFACES §1 constants "
            "red_vm=%s blue_vm=%s attack_mode=%s",
            exc,
            DEFAULT_RED_VM,
            DEFAULT_BLUE_VM,
            DEFAULT_ATTACK_MODE,
        )
        return VMConfig(
            red_vm=DEFAULT_RED_VM,
            blue_vm=DEFAULT_BLUE_VM,
            attack_mode=DEFAULT_ATTACK_MODE,
            source="interfaces-§1-constants",
        )

    records = _read_dataset_records(dataset)
    record = records[0]
    if not isinstance(record, Mapping):
        raise DatasetConfigError(f"dataset {dataset} first record must be a JSON object")
    missing = [
        key
        for key in ("red_vm_name", "blue_vm_name", "attack_mode")
        if not str(record.get(key) or "").strip()
    ]
    if missing:
        raise DatasetConfigError(
            f"dataset {dataset} first record is missing {missing}; refusing to guess VM names "
            f"Fix the dataset, or pin {RED_VM_ENV}/{BLUE_VM_ENV}/{ATTACK_MODE_ENV}."
        )

    config = VMConfig(
        red_vm=str(record["red_vm_name"]).strip(),
        blue_vm=str(record["blue_vm_name"]).strip(),
        attack_mode=str(record["attack_mode"]).strip(),
        source=f"dataset:{dataset}",
        dataset_path=dataset,
    )
    logger.info("VM config from dataset %s: %s", dataset, config)
    return _warn_on_contract_mismatch(config)


#: Public alias of the helper name.
_read_vm_config = read_vm_config


def _warn_on_contract_mismatch(config: VMConfig) -> VMConfig:
    """Log (do not silently rewrite) values that disagree with INTERFACES §1."""
    if config.red_vm != DEFAULT_RED_VM or config.blue_vm != DEFAULT_BLUE_VM:
        logger.warning(
            "VM pair %s/%s differs from the INTERFACES §1 constants %s/%s (source: %s)",
            config.red_vm,
            config.blue_vm,
            DEFAULT_RED_VM,
            DEFAULT_BLUE_VM,
            config.source,
        )
    if config.attack_mode not in SUPPORTED_ATTACK_MODES:
        logger.warning(
            "attack_mode %r is outside the supported set %s (INTERFACES §1)",
            config.attack_mode,
            list(SUPPORTED_ATTACK_MODES),
        )
    return config


def soc_endpoint() -> str:
    """Return the SOC endpoint from ``SOAR_ABILITY_ENDPOINT`` (INTERFACES §1)."""
    return (os.environ.get(SOC_ENDPOINT_ENV) or "").strip() or DEFAULT_SOC_ENDPOINT


def round_timeout_s() -> float:
    """Return the per-round SOC read timeout from ``SOAR_ROUND_TIMEOUT_S``.

    Defaults to :data:`DEFAULT_ROUND_TIMEOUT_S`, which is deliberately larger than the
    SOC's attack budget -- see that constant for why a small value cannot work.

    A blank value means "unset".  An unparsable or non-positive value is a
    configuration error and raises :class:`SOCError` rather than being quietly ignored:
    silently falling back to a small timeout is precisely the failure this setting
    exists to prevent, and it would hide itself until the first long round.
    """
    raw = (os.environ.get(ROUND_TIMEOUT_ENV) or "").strip()
    if not raw:
        return DEFAULT_ROUND_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError as exc:
        raise SOCError(f"{ROUND_TIMEOUT_ENV}={raw!r} is not a number of seconds") from exc
    if value <= 0:
        raise SOCError(f"{ROUND_TIMEOUT_ENV}={raw!r} must be positive")
    return value


def _coerce_strategy(strategy: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalise a strategy to the canonical ``[{"tool": ..., "params": {...}}]`` shape."""
    if isinstance(strategy, (str, bytes)) or not isinstance(strategy, Sequence):
        raise SOCError(f"strategy must be a sequence of tool calls, got {type(strategy).__name__}")
    if not strategy:
        raise SOCError("strategy is empty; nothing to deploy")
    normalised: list[dict[str, Any]] = []
    for index, call in enumerate(strategy):
        if not isinstance(call, Mapping):
            raise SOCError(f"strategy entry #{index} must be an object with a 'tool' key")
        tool = str(call.get("tool") or "").strip()
        if not tool:
            raise SOCError(f"strategy entry #{index} has no 'tool' name")
        params = call.get("params", call.get("parameters", {})) or {}
        if not isinstance(params, Mapping):
            raise SOCError(f"strategy entry #{index} ('{tool}') has non-object 'params'")
        normalised.append({"tool": tool, "params": dict(params)})
    return normalised


class BatchExecutor:
    """Submits a **whole** defence strategy to the SOC in exactly one request.

    The SOC deploys every tool at once, runs the attack once and measures the 3-D
    feedback vector (INTERFACES §5), so ``rs_exe`` and ``rs_attack`` come from the same
    deployment and the same attack.

    ``timeout_s`` defaults to :func:`round_timeout_s` (``SOAR_ROUND_TIMEOUT_S``), i.e.
    large enough to outlive the SOC's own attack budget.  Pass a value explicitly only
    when you deliberately want to stop waiting sooner.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        *,
        timeout_s: float | None = None,
        session: requests.Session | None = None,
        vm_config: VMConfig | None = None,
    ) -> None:
        self.endpoint = (endpoint or soc_endpoint()).strip()
        if not self.endpoint:
            raise SOCError("SOC endpoint is empty; set SOAR_ABILITY_ENDPOINT (INTERFACES §1)")
        self.timeout_s = round_timeout_s() if timeout_s is None else float(timeout_s)
        self._session = session or requests.Session()
        self._vm_config = vm_config

    # -- helpers -----------------------------------------------------------------------
    def _base_url(self) -> str:
        parts = urlsplit(self.endpoint)
        return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else self.endpoint

    def vm_config(self) -> VMConfig:
        """Cached VM configuration (read once per executor)."""
        if self._vm_config is None:
            self._vm_config = read_vm_config()
        return self._vm_config

    def health_check(self, *, timeout_s: float = 10.0) -> dict[str, Any]:
        """``GET /health`` (INTERFACES §3.2).  Raises :class:`SOCUnavailableError`."""
        url = f"{self._base_url()}/health"
        try:
            response = self._session.get(url, timeout=timeout_s)
        except requests.RequestException as exc:
            raise SOCUnavailableError(f"SOC health endpoint {url} unreachable: {exc}") from exc
        if response.status_code != 200:
            raise SOCUnavailableError(
                f"SOC health endpoint {url} returned HTTP {response.status_code}: "
                f"{(response.text or '').strip()[:200]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise SOCError(f"SOC health endpoint {url} returned a non-JSON body") from exc
        return payload if isinstance(payload, dict) else {"raw": payload}

    def capabilities(self, *, vm: str | None = None, timeout_s: float = 60.0) -> dict[str, Any]:
        """``GET /capabilities`` — what the target can actually run (§3.2).

        This is the source of ``T_A`` (paper Eq. 3: *the tools available in the current
        environment*). It is a **measurement**, so a failure is reported instead of being
        papered over with a plausible tool list -- a plausible list is what lets a Linux
        prompt advertise a Windows-only tool.

        Raises:
            SOCUnavailableError: the SOC endpoint is unreachable, or could not probe.
            SOCError: the SOC answered with a body this client does not understand.
        """
        url = f"{self._base_url()}/capabilities"
        params = {"vm": vm} if vm else None
        try:
            response = self._session.get(url, timeout=timeout_s, params=params)
        except requests.RequestException as exc:
            raise SOCUnavailableError(f"SOC capabilities endpoint {url} unreachable: {exc}") from exc
        if response.status_code != 200:
            raise SOCUnavailableError(
                f"SOC capabilities endpoint {url} returned HTTP {response.status_code}: "
                f"{(response.text or '').strip()[:200]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise SOCError(f"SOC capabilities endpoint {url} returned a non-JSON body") from exc
        if not isinstance(payload, dict) or "available_tools" not in payload:
            raise SOCError(
                f"SOC capabilities endpoint {url} returned an unexpected body: "
                f"{str(payload)[:200]}"
            )
        return payload

    # -- the single request ------------------------------------------------------------
    def submit_strategy(
        self,
        strategy: Sequence[Mapping[str, Any]],
        *,
        red_vm: str | None = None,
        blue_vm: str | None = None,
        attack_mode: str | None = None,
        timeout_s: float | None = None,
    ) -> dict[str, Any]:
        """POST the canonical ``{"strategy": [...]}`` body and return the SOC response.

        Exactly one HTTP request is issued, whatever the number of tools.

        Raises:
            SOCError: the strategy is structurally invalid.
            SOCUnavailableError: transport failure, timeout or non-200 status.
        """
        calls = _coerce_strategy(strategy)
        vm = self.vm_config()
        payload: dict[str, Any] = {"strategy": calls}
        payload.update(
            {
                "attack_mode": attack_mode or vm.attack_mode,
                "red_vm": red_vm or vm.red_vm,
                "blue_vm": blue_vm or vm.blue_vm,
            }
        )
        timeout = float(timeout_s if timeout_s is not None else self.timeout_s)
        logger.info(
            "submitting %d-tool strategy in ONE request to %s (attack_mode=%s, red_vm=%s, blue_vm=%s)",
            len(calls),
            self.endpoint,
            payload["attack_mode"],
            payload["red_vm"],
            payload["blue_vm"],
        )
        response = self._post_with_retry(payload, timeout=timeout)
        try:
            body = response.json()
        except ValueError as exc:
            raise SOCError(
                f"SOC endpoint {self.endpoint} returned a non-JSON body: "
                f"{(response.text or '')[:200]!r}"
            ) from exc
        if not isinstance(body, dict):
            raise SOCError(f"SOC endpoint {self.endpoint} returned {type(body).__name__}, expected an object")
        return body

    # -- capacity exhaustion (INTERFACES §3.1) ------------------------------------------
    def _post_with_retry(self, payload: dict[str, Any], *, timeout: float) -> requests.Response:
        """POST the payload, honouring ``429`` + ``Retry-After`` (INTERFACES §3.1).

        The contract requires ``429`` (capacity exhausted, **retryable**) and
        ``200 + success:false`` (the strategy itself failed, **not** retryable) to be
        handled differently. This client keeps them apart: ``429`` becomes
        :class:`SOCBusyError` and any other transport failure becomes
        :class:`SOCUnavailableError`, so a busy VM pool never teaches the policy that a
        perfectly good strategy had failed.

        Retries: ``429`` and transient transport errors, up to
        ``SECLOOP_RETRY_ATTEMPTS`` (default 4) with exponential backoff seeded by the
        server's ``Retry-After`` (seconds or an HTTP date), capped so a hostile or buggy
        header cannot stall a training run (``SECLOOP_RETRY_MAX_SLEEP_S``, default 60).

        Raises:
            SOCBusyError: capacity stayed exhausted for the whole budget. **Retryable** --
                callers must exclude the sample rather than score it.
            SOCUnavailableError: another transport failure, or a non-200 that is not 429.
        """
        attempts = max(1, int(os.getenv(RETRY_ATTEMPTS_ENV, "4")))
        max_sleep = float(os.getenv(RETRY_MAX_SLEEP_ENV, "60"))
        last_error = "no attempt was made"

        for attempt in range(1, attempts + 1):
            try:
                response = self._session.post(self.endpoint, json=payload, timeout=timeout)
            except requests.RequestException as exc:
                last_error = f"SOC endpoint {self.endpoint} unreachable: {exc}"
                if attempt == attempts:
                    break
                self._sleep_for_retry(attempt, None, max_sleep, reason=str(exc))
                continue

            if response.status_code == 429:
                last_error = (
                    f"SOC endpoint {self.endpoint} returned HTTP 429 (capacity exhausted): "
                    f"{(response.text or '').strip()[:200]}"
                )
                if attempt == attempts:
                    raise SOCBusyError(
                        f"{last_error}. Retried {attempts} time(s); the VM pool stayed busy. "
                        f"This is a retryable transport failure, not a verdict on the "
                        f"strategy, so the sample must be excluded rather than scored 0."
                    ) from None
                self._sleep_for_retry(
                    attempt, response.headers.get("Retry-After"), max_sleep, reason="HTTP 429"
                )
                continue

            if response.status_code != 200:
                raise SOCUnavailableError(
                    f"SOC endpoint {self.endpoint} returned HTTP {response.status_code}: "
                    f"{(response.text or '').strip()[:300]}"
                )
            if attempt > 1:
                logger.info("SOC request succeeded on attempt %d/%d", attempt, attempts)
            return response

        raise SOCUnavailableError(f"{last_error} (after {attempts} attempt(s))")

    @staticmethod
    def _sleep_for_retry(
        attempt: int, retry_after: str | None, max_sleep: float, *, reason: str
    ) -> None:
        """Sleep before retry ``attempt + 1``, preferring the server's ``Retry-After``."""
        delay = parse_retry_after(retry_after)
        if delay is None:
            delay = min(2.0 ** (attempt - 1), max_sleep)  # 1s, 2s, 4s, ...
        delay = max(0.0, min(float(delay), max_sleep))
        logger.warning(
            "SOC request backing off %.1fs (attempt %d, %s)", delay, attempt, reason
        )
        time.sleep(delay)

    def execute_strategy(
        self,
        strategy: Sequence[Mapping[str, Any]],
        *,
        red_vm: str | None = None,
        blue_vm: str | None = None,
        attack_mode: str | None = None,
        timeout_s: float | None = None,
    ) -> dict[str, Any]:
        """Submit a strategy once and return it together with the full feedback vector.

        The returned mapping carries ``success`` / ``score`` / ``error`` / ``elapsed_s``,
        the normalised input ``strategy``, the SOC's ``feedback`` object, the per-tool
        entries (``tools``) and the four §4 fields (``rs_exe``, ``rs_attack``,
        ``rs_service``, ``F_i``) as top-level conveniences.  Values are relayed verbatim —
        they are **never** defaulted to ``0.0`` when the SOC omitted them.
        """
        calls = _coerce_strategy(strategy)
        body = self.submit_strategy(
            calls,
            red_vm=red_vm,
            blue_vm=blue_vm,
            attack_mode=attack_mode,
            timeout_s=timeout_s,
        )

        feedback = body.get("feedback")
        if not isinstance(feedback, Mapping):
            logger.warning(
                "SOC response carries no 'feedback' object (INTERFACES §3.1); "
                "the 3-D vector is unavailable for this round"
            )
            feedback = {}

        for key in ("rs_exe", "rs_attack", "rs_service", "F_i"):
            if key not in feedback:
                logger.warning("SOC feedback is missing the INTERFACES §4 field %r", key)

        tools = feedback.get("tools")
        tools = list(tools) if isinstance(tools, list) else []

        result: dict[str, Any] = {
            "success": bool(body.get("success", False)),
            "score": body.get("score"),
            "error": body.get("error"),
            "attack_mode": body.get("attack_mode"),
            "elapsed_s": body.get("elapsed_s"),
            "endpoint": self.endpoint,
            "strategy": calls,
            "feedback": dict(feedback),
            "tools": tools,
            "rs_exe": feedback.get("rs_exe"),
            "rs_attack": feedback.get("rs_attack"),
            "rs_service": feedback.get("rs_service"),
            "F_i": feedback.get("F_i"),
        }
        if not result["success"]:
            logger.error("SOC reported a failed round: %s", result["error"])
        return result

    def execute_tool(
        self,
        tool: str,
        params: Mapping[str, Any] | None = None,
        *,
        red_vm: str | None = None,
        blue_vm: str | None = None,
        attack_mode: str | None = None,
        timeout_s: float | None = None,
    ) -> dict[str, Any]:
        """Execute a **single** tool (a one-element strategy, still one request).

        This is for standalone/diagnostic use only.  Running a multi-tool strategy must
        always go through :meth:`execute_strategy` so the combination is evaluated once.
        """
        single = [{"tool": tool, "params": dict(params or {})}]
        result = self.execute_strategy(
            single,
            red_vm=red_vm,
            blue_vm=blue_vm,
            attack_mode=attack_mode,
            timeout_s=timeout_s,
        )
        entry: Mapping[str, Any] = {}
        for candidate in result["tools"]:
            if isinstance(candidate, Mapping) and str(candidate.get("tool") or "") == tool:
                entry = candidate
                break
        return {
            "tool": tool,
            "params": dict(params or {}),
            "success": bool(entry.get("success", result["success"])),
            "output": entry.get("output"),
            "error": entry.get("error"),
            "feedback": result["feedback"],
            "rs_exe": result["rs_exe"],
            "rs_attack": result["rs_attack"],
            "rs_service": result["rs_service"],
            "F_i": result["F_i"],
        }

    @staticmethod
    def compute_rs_exe(tool_results: Sequence[Mapping[str, Any]]) -> float:
        """``rs_exe`` per Eq.10 — pure helper, no network access.

        ``rs_exe(S_i) = (1/l) * Σ f_exe(t_j)``.  An empty strategy returns ``0.0``
        (INTERFACES §4.1 rule 2: empty segments score ``0.0``, never ``1.0``).
        """
        if not tool_results:
            logger.warning("compute_rs_exe called with no tool results; returning 0.0 (INTERFACES §4.1)")
            return 0.0
        successes = sum(1 for result in tool_results if result.get("success", False))
        return round(successes / len(tool_results), 4)
