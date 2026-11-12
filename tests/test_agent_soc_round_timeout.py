# SPDX-License-Identifier: Apache-2.0
"""The agent must be willing to wait for as long as the SOC is allowed to work.

Why this test exists
--------------------
A ``POST /execute_ability`` is not a quick RPC.  One round waits for a free VM pair,
deploys the strategy, runs a **whole attack**, and rolls the blue-team snapshot back.
The SOC budgets ``SOC_ATTACK_TIMEOUT_S`` (default 900 s) for the attack alone, and a
full-length SQLi probe genuinely takes minutes: measured rounds on real hardware ran
**212.9 s** (undefended) and **126.5 s** (blocked), and the raw responses are committed
from a measured round.  A round's wall time depends on how far a time-blind attack
gets before it succeeds or exhausts its budget, so treat those as samples, not as an
expected duration.

``BatchExecutor`` must not hang up while the SOC is still allowed to work.  A round
also waits for a pool slot (300 s) and performs a rollback whose ``snapshot_list`` and
``snapshot_restore`` are each bounded by a **separate** 900 s watchdog, so the client's
default has to cover the whole of that.  The tests below therefore do not pin a number;
they re-derive the SOC's worst case from the SOC's own source and assert the client
outlasts it, so the two subsystems cannot drift apart in either direction.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent.tools.batch_executor import (
    DEFAULT_ROUND_TIMEOUT_S,
    ROUND_TIMEOUT_ENV,
    SOC_ATTACK_BUDGET_S,
    SOC_OTHER_STEPS,
    SOC_POOL_ACQUIRE_S,
    SOC_SNAPSHOT_WATCHDOG_S,
    SOC_SSH_GRACE_S,
    SOC_SSH_STEP_S,
    SOCError,
    BatchExecutor,
    round_timeout_s,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
RED_TEAM_CONTROLLER = REPO_ROOT / "battlefield" / "soc" / "red_team_controller.py"
VAGRANT_DRIVER = REPO_ROOT / "battlefield" / "soc" / "vagrant_driver.py"
VM_POOL = REPO_ROOT / "battlefield" / "soc" / "vm_pool.py"


def soc_constant(path: Path, name: str) -> float:
    """Read a module-level float constant out of a SOC source file.

    Read from source rather than imported on purpose: ``python-vagrant`` is not
    installed in the test environment, and although ``vagrant_driver`` defers that
    import to call time -- so the package does import cleanly -- binding these numbers
    to a real import would make the contract test depend on a lab-only library for no
    benefit.
    """
    source = path.read_text(encoding="utf-8")
    match = re.search(rf"^{name}\s*=\s*([0-9.]+)", source, re.MULTILINE)
    assert match, f"could not find {name} in {path}"
    return float(match.group(1))


def soc_default_attack_timeout() -> float:
    return soc_constant(RED_TEAM_CONTROLLER, "DEFAULT_ATTACK_TIMEOUT_S")


def soc_worst_case_round_s() -> float:
    """The SOC's own worst-case wall clock for one round, from its own budgets.

    Mirrors the derivation documented at ``batch_executor.DEFAULT_ROUND_TIMEOUT_S``:
    waiting for a VM pair, the attack budget plus SSH grace, the closing rollback
    (which lists and then restores, each bounded by the *snapshot* watchdog
    separately) and the remaining watchdog-bounded SSH steps.
    """
    return (
        soc_constant(VM_POOL, "DEFAULT_POOL_TIMEOUT_S")
        + soc_constant(RED_TEAM_CONTROLLER, "DEFAULT_ATTACK_TIMEOUT_S")
        + soc_constant(VAGRANT_DRIVER, "SSH_WATCHDOG_GRACE_S")
        + 2 * soc_constant(VAGRANT_DRIVER, "SNAPSHOT_WATCHDOG_S")
        + SOC_OTHER_STEPS
        * (
            soc_constant(VAGRANT_DRIVER, "DEFAULT_SSH_TIMEOUT_S")
            + soc_constant(VAGRANT_DRIVER, "SSH_WATCHDOG_GRACE_S")
        )
    )


def test_soc_attack_budget_is_still_900() -> None:
    """Pin the number the agent's default is measured against."""
    assert soc_default_attack_timeout() == 900.0


def test_client_mirrors_match_the_soc_budgets() -> None:
    """The mirrored copies must equal the SOC's real budgets, or the derivation lies.

    ``batch_executor`` deliberately mirrors the SOC's phase budgets as literals so a
    reader can check the arithmetic without importing ``battlefield``.  This test is
    what stops a mirror going stale.
    """
    assert SOC_POOL_ACQUIRE_S == soc_constant(VM_POOL, "DEFAULT_POOL_TIMEOUT_S")
    assert SOC_ATTACK_BUDGET_S == soc_constant(RED_TEAM_CONTROLLER, "DEFAULT_ATTACK_TIMEOUT_S")
    assert SOC_SSH_GRACE_S == soc_constant(VAGRANT_DRIVER, "SSH_WATCHDOG_GRACE_S")
    assert SOC_SNAPSHOT_WATCHDOG_S == soc_constant(VAGRANT_DRIVER, "SNAPSHOT_WATCHDOG_S")
    assert SOC_SSH_STEP_S == soc_constant(VAGRANT_DRIVER, "DEFAULT_SSH_TIMEOUT_S")


def test_default_round_timeout_covers_the_soc_worst_case() -> None:
    """The agent must not give up while the SOC is still allowed to be working.

    A default that covered only the attack budget (960 s) would, on a host whose
    snapshots are slow, raise ``ReadTimeout`` mid-round: ``_run_strategy`` would record
    ``None`` and the reward would record ``R_exec = R_eva = 0.0`` for a round that had in
    fact been measured, while the SOC kept the VM pair busy.
    """
    worst = soc_worst_case_round_s()
    assert DEFAULT_ROUND_TIMEOUT_S >= worst, (
        f"the agent would time out after {DEFAULT_ROUND_TIMEOUT_S}s while the SOC is "
        f"still allowed to work for up to {worst}s (pool acquire + attack + grace + "
        f"snapshot rollback + other SSH steps)"
    )


def test_env_override_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ROUND_TIMEOUT_ENV, "1800")
    assert round_timeout_s() == 1800.0


def test_blank_env_means_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ROUND_TIMEOUT_ENV, "   ")
    assert round_timeout_s() == DEFAULT_ROUND_TIMEOUT_S


def test_unset_env_falls_back_to_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ROUND_TIMEOUT_ENV, raising=False)
    assert round_timeout_s() == DEFAULT_ROUND_TIMEOUT_S


def test_unparsable_env_is_a_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo must fail loudly; silently using a small timeout hides until round 1."""
    monkeypatch.setenv(ROUND_TIMEOUT_ENV, "15m")
    with pytest.raises(SOCError, match="not a number"):
        round_timeout_s()


@pytest.mark.parametrize("value", ["0", "-1", "-0.5"])
def test_non_positive_env_is_a_config_error(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(ROUND_TIMEOUT_ENV, value)
    with pytest.raises(SOCError, match="must be positive"):
        round_timeout_s()


def test_executor_defaults_to_the_round_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """``BatchExecutor()`` with no arguments must use the generous default.

    Both call sites construct it with no arguments, so the default is what they get.
    """
    monkeypatch.delenv(ROUND_TIMEOUT_ENV, raising=False)
    assert BatchExecutor().timeout_s == DEFAULT_ROUND_TIMEOUT_S

    monkeypatch.setenv(ROUND_TIMEOUT_ENV, "1234.5")
    assert BatchExecutor().timeout_s == 1234.5


def test_explicit_timeout_still_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit value overrides both the env var and the default."""
    monkeypatch.setenv(ROUND_TIMEOUT_ENV, "1800")
    assert BatchExecutor(timeout_s=5.0).timeout_s == 5.0
