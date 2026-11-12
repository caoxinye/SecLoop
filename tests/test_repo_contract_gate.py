# SPDX-License-Identifier: Apache-2.0
"""Run the repository's invariant gate, so its own failure can never be silent.

`tests/check_repo_contract.py` is the enforcer of the frozen contract: several documents
(``conftest.py``, ``docs/INTERFACES.md`` §12, ``docs/quickstart.md``)
point at it as the thing that keeps the repository honest.

A gate that crashes after its last check and before its summary prints no PASS/FAIL line
at all, and a gate that no test invokes can regress without anything noticing.  So this
file invokes it, and requires both the exit status and the summary.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE = REPO_ROOT / "tests" / "check_repo_contract.py"


def run_gate() -> subprocess.CompletedProcess:
    # `-B`: the gate scans the *live* tree for `__pycache__`, and a child process does not
    # inherit `sys.dont_write_bytecode`.  Without this the gate can fail on bytecode that
    # this very test session just created -- a self-inflicted failure that reads as a
    # repository failure, so `PYTHONDONTWRITEBYTECODE=1` is required, not optional.
    return subprocess.run(
        [sys.executable, "-B", str(GATE)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )


def test_the_gate_exists() -> None:
    assert GATE.is_file(), f"the contract gate is missing: {GATE}"


def test_the_gate_runs_to_completion_and_passes() -> None:
    result = run_gate()
    combined = result.stdout + result.stderr
    assert result.returncode == 0, (
        "tests/check_repo_contract.py did not pass.\n"
        f"--- stdout (tail) ---\n{result.stdout[-3000:]}\n"
        f"--- stderr (tail) ---\n{result.stderr[-2000:]}"
    )
    # A crash after the last check but before the summary looks like this: exit code 1, a
    # traceback, and no PASS/FAIL line. Require the summary.
    assert "PASS " in combined and "FAIL " in combined, (
        f"the gate produced no PASS/FAIL summary (it probably crashed):\n{result.stdout[-3000:]}"
    )
    match = re.search(r"PASS (\d+)\s+FAIL (\d+)\s+WARN (\d+)", combined)
    assert match, f"could not read the gate's summary line:\n{result.stdout[-2000:]}"
    passes, failures, warnings = (int(group) for group in match.groups())
    assert failures == 0, f"the gate reported {failures} blocking failure(s)"
    assert warnings == 0, f"the gate reported {warnings} warning(s)"
    assert passes >= 40, f"only {passes} checks ran; checks are probably being skipped"


def test_the_gate_reports_every_contract_check() -> None:
    """Checks from several gate sections whose PASS lines must appear in its output."""
    combined = run_gate().stdout
    for phrase in (
        "accepts the discovered tool set",
        "routes GET /capabilities",
        "defines resolve_row_environment()",
        "renders T_A from an environment argument",
        "no tool list that could contradict",
    ):
        assert phrase in combined, f"the gate does not report: {phrase}"
