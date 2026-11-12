# SPDX-License-Identifier: Apache-2.0
"""Lock-protected BATTLE-FIELD VM pool (``docs/INTERFACES.md`` §3.3).

One pair is ``(red VM, blue VM)`` and one pair serves exactly one
``POST /execute_ability`` round at a time, because a round deploys a strategy on
the blue VM, attacks it, and finally restores the blue VM's initial snapshot.

Occupancy in a plain ``dict`` with no lock would let two
concurrent requests be handed the same pair and interleave their
deploy/attack/restore steps.  Here acquisition and release happen under one
``threading.Condition`` and a released pair is handed to the next waiter.

Default: **one** pair, ``kali`` (192.168.57.199) + ``target`` (192.168.57.200).
Extend it with ``SOAR_VM_POOL``::

    SOAR_VM_POOL='[{"name":"pair-0","red_vm":"kali","blue_vm":"target"},
                   {"name":"pair-1","red_vm":"kali2","blue_vm":"target2"}]'
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

logger = logging.getLogger(__name__)

__all__ = ["DEFAULT_VM_POOL", "VmPair", "VmPool", "VmPoolExhausted"]

VM_POOL_ENV = "SOAR_VM_POOL"
POOL_TIMEOUT_ENV = "SOC_POOL_TIMEOUT_S"
DEFAULT_POOL_TIMEOUT_S = 300.0
DEFAULT_ATTACK_MODE = "sqli"


class VmPoolExhausted(RuntimeError):
    """Raised when no VM pair became free within the acquire timeout."""


@dataclass(frozen=True)
class VmPair:
    """One BATTLE-FIELD environment ``E_k = (E_RVM, E_BVM)``."""

    name: str
    red_vm: str
    blue_vm: str
    attack_mode: str | None = DEFAULT_ATTACK_MODE


#: `docs/INTERFACES.md` §3.3: default one pair, ``kali`` + ``target``.
DEFAULT_VM_POOL: tuple[VmPair, ...] = (
    VmPair(name="pair-0", red_vm="kali", blue_vm="target", attack_mode=DEFAULT_ATTACK_MODE),
)


class VmPool:
    """A concurrency-safe set of VM pairs."""

    def __init__(
        self,
        pairs: Sequence[VmPair] | None = None,
        *,
        default_timeout_s: float = DEFAULT_POOL_TIMEOUT_S,
    ) -> None:
        resolved = list(pairs) if pairs else list(DEFAULT_VM_POOL)
        names = [pair.name for pair in resolved]
        if len(set(names)) != len(names):
            logger.warning("VmPool: duplicate pair names in %s; keeping the first of each", names)
            seen: set[str] = set()
            unique: list[VmPair] = []
            for pair in resolved:
                if pair.name in seen:
                    continue
                seen.add(pair.name)
                unique.append(pair)
            resolved = unique
        if not resolved:
            raise ValueError("VmPool needs at least one pair")
        self._pairs: tuple[VmPair, ...] = tuple(resolved)
        self._in_use: set[str] = set()
        self._condition = threading.Condition(threading.Lock())
        self.default_timeout_s = float(default_timeout_s)

    # ------------------------------------------------------------ factories

    @classmethod
    def from_env(cls, *, default_attack_mode: str = DEFAULT_ATTACK_MODE) -> VmPool:
        """Build the pool from ``SOAR_VM_POOL``, falling back to the default pair.

        Malformed entries are reported and dropped; a pool that ends up empty
        falls back to the default pair rather than leaving the SOC unusable.
        """
        timeout = float(os.getenv(POOL_TIMEOUT_ENV, DEFAULT_POOL_TIMEOUT_S))
        raw = os.getenv(VM_POOL_ENV)
        if not raw:
            return cls(list(DEFAULT_VM_POOL), default_timeout_s=timeout)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("%s is not valid JSON (%s); using the default VM pair", VM_POOL_ENV, exc)
            return cls(list(DEFAULT_VM_POOL), default_timeout_s=timeout)

        if not isinstance(data, list) or not data:
            logger.warning("%s must be a non-empty JSON array; using the default VM pair", VM_POOL_ENV)
            return cls(list(DEFAULT_VM_POOL), default_timeout_s=timeout)

        pairs: list[VmPair] = []
        for index, item in enumerate(data):
            if not isinstance(item, Mapping):
                logger.warning("%s[%d] is not an object; skipped", VM_POOL_ENV, index)
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                legacy = item.get("id")  # legacy key, tolerated
                if isinstance(legacy, str) and legacy.strip():
                    logger.warning(
                        "%s[%d] uses the legacy 'id' key; the contract uses 'name'",
                        VM_POOL_ENV,
                        index,
                    )
                    name = legacy
            red_vm = item.get("red_vm")
            blue_vm = item.get("blue_vm")
            if not all(isinstance(value, str) and value.strip() for value in (name, red_vm, blue_vm)):
                logger.warning(
                    "%s[%d] needs string 'name', 'red_vm' and 'blue_vm'; skipped",
                    VM_POOL_ENV,
                    index,
                )
                continue
            attack_mode = item.get("attack_mode") or item.get("default_attack_mode") or default_attack_mode
            pairs.append(
                VmPair(
                    name=str(name).strip(),
                    red_vm=str(red_vm).strip(),
                    blue_vm=str(blue_vm).strip(),
                    attack_mode=str(attack_mode),
                )
            )
        if not pairs:
            logger.warning("no usable entries in %s; using the default VM pair", VM_POOL_ENV)
            return cls(list(DEFAULT_VM_POOL), default_timeout_s=timeout)
        logger.info("VmPool: %d pair(s) configured from %s", len(pairs), VM_POOL_ENV)
        return cls(pairs, default_timeout_s=timeout)

    # -------------------------------------------------------------- lifecycle

    def acquire(
        self, timeout_s: float | None = None, preferred: str | None = None
    ) -> VmPair:
        """Take a free pair, waiting up to ``timeout_s`` for one.

        Raises:
            VmPoolExhausted: no pair became free in time (or ``preferred`` is not
                part of this pool).
        """
        budget = float(timeout_s if timeout_s is not None else self.default_timeout_s)
        if preferred is not None and preferred not in {pair.name for pair in self._pairs}:
            raise VmPoolExhausted(
                f"unknown pair {preferred!r}; configured pairs: "
                f"{', '.join(pair.name for pair in self._pairs)}"
            )
        deadline = time.monotonic() + budget
        with self._condition:
            while True:
                for pair in self._pairs:
                    if pair.name in self._in_use:
                        continue
                    if preferred is not None and pair.name != preferred:
                        continue
                    self._in_use.add(pair.name)
                    logger.info("VmPool: acquired %s (%s/%s)", pair.name, pair.red_vm, pair.blue_vm)
                    return pair
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise VmPoolExhausted(
                        f"no VM pair free after {budget:.0f}s "
                        f"(pool size {len(self._pairs)}, all in use)"
                    )
                logger.info(
                    "VmPool: all %d pair(s) busy; waiting up to %.0fs for one",
                    len(self._pairs),
                    remaining,
                )
                self._condition.wait(remaining)

    def release(self, pair: VmPair | str) -> None:
        """Give a pair back and wake one waiter."""
        name = pair.name if isinstance(pair, VmPair) else str(pair)
        with self._condition:
            if name not in self._in_use:
                logger.warning("VmPool: release of %r which is not currently in use", name)
                return
            self._in_use.discard(name)
            self._condition.notify_all()
            logger.info("VmPool: released %s", name)

    # ----------------------------------------------------------------- views

    @property
    def size(self) -> int:
        """Number of pairs in the pool (``GET /health`` -> ``vm_pool_size``)."""
        return len(self._pairs)

    @property
    def in_use_count(self) -> int:
        """Number of pairs currently checked out."""
        with self._condition:
            return len(self._in_use)

    def pairs_status(self) -> list[dict[str, object]]:
        """``GET /pairs`` payload (``docs/INTERFACES.md`` §3.2)."""
        with self._condition:
            return [
                {
                    "name": pair.name,
                    "red_vm": pair.red_vm,
                    "blue_vm": pair.blue_vm,
                    "in_use": pair.name in self._in_use,
                }
                for pair in self._pairs
            ]

    def get(self, name: str) -> VmPair | None:
        """Look a pair up by name."""
        for pair in self._pairs:
            if pair.name == name:
                return pair
        return None
