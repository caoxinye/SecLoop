# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the offline SecLoop lab tests.

These tests are deliberately **VM-free and dependency-free**: standard library
only, no PHP, MySQL, Apache, Suricata or network access.  They verify the two
halves of the reference scenario that can be checked on any laptop:

* ``battlefield/attacks/sqli_lab.py`` -- the ``[RESULT]`` contract, the five
  weighted stages, graceful degradation and the lab-IP guard, driven through the
  real ``main()`` over a simulated transport and clock;
* ``ids/combine_ids_log.py`` -- the Eq.2 alert summarizer, over a small
  hand-authored ``fast.log`` fixture.

Each test module is both pytest-collectable and a standalone script::

    python tests/lab/test_sqli_probe.py          # standalone, stdlib only
    python -m pytest tests/lab -q                # if pytest is available

Running these tests must never leave bytecode in the repository, so this module
switches bytecode writing off process-wide on import (the repo contract forbids
committed ``__pycache__``/``*.pyc``).
"""

from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path
from types import ModuleType

sys.dont_write_bytecode = True

#: ``tests/lab`` -> repo root.
LAB_DIR = Path(__file__).resolve().parent
REPO_ROOT = LAB_DIR.parent.parent
FIXTURE_DIR = LAB_DIR / "fixtures"

#: Hand-authored fast.log fixture (NOT captured evidence -- see its header).
FASTLOG_FIXTURE = FIXTURE_DIR / "fastlog_parser_fixture.txt"

#: Modules under test.
SQLI_LAB_PATH = REPO_ROOT / "battlefield" / "attacks" / "sqli_lab.py"
SUMMARIZER_PATH = REPO_ROOT / "ids" / "combine_ids_log.py"
SURICATA_RULES_PATH = REPO_ROOT / "target" / "suricata" / "local.rules"

#: The lab rules start here (docs/INTERFACES.md section 11).  The contract is
#: "at least ``LOCAL_SID_MIN_RULES`` rules, numbered consecutively from here" -- not an
#: exact set, so the documented "add a Suricata rule" extension step does not redden
#: the suite.
LOCAL_SID_START = 1000001
LOCAL_SID_MIN_RULES = 6


def local_sid_sequence(count: int) -> list[int]:
    """The first ``count`` local sids: ``1000001, 1000002, ...``."""
    return list(range(LOCAL_SID_START, LOCAL_SID_START + count))


def is_consecutive_local_sids(sids: list[int]) -> bool:
    """True when ``sids`` is exactly ``1000001..N`` with no gaps and no strays."""
    return sorted(sids) == local_sid_sequence(len(sids))


class SkipCheck(Exception):
    """Raised by :func:`skip` when pytest is not the driver."""


def skip(reason: str) -> None:
    """Skip the current test: a real pytest skip, or a printed skip standalone."""
    pytest = sys.modules.get("pytest")
    if pytest is not None:
        pytest.skip(reason)
    raise SkipCheck(reason)


def load_module(name: str, path: Path) -> ModuleType:
    """Import a repository module by file path.

    The repo is not an installed package, so the modules under test are loaded
    directly.  ``sys.modules`` is populated *before* execution because
    ``dataclasses`` resolves string annotations through ``sys.modules`` when a
    module uses ``from __future__ import annotations``.
    """
    if not path.is_file():
        raise FileNotFoundError(f"module under test is missing: {path}")
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_sqli_lab() -> ModuleType:
    """Return ``battlefield/attacks/sqli_lab.py`` as a module."""
    return load_module("secloop_under_test_sqli_lab", SQLI_LAB_PATH)


def load_summarizer() -> ModuleType:
    """Return ``ids/combine_ids_log.py`` as a module."""
    return load_module("secloop_under_test_summarizer", SUMMARIZER_PATH)


def read_fixture_lines() -> list[str]:
    """Return the fast.log fixture as a list of lines, without line endings."""
    if not FASTLOG_FIXTURE.is_file():
        raise FileNotFoundError(f"fixture is missing: {FASTLOG_FIXTURE}")
    return FASTLOG_FIXTURE.read_text(encoding="utf-8").splitlines()


def run_module_tests(namespace: dict) -> int:
    """Standalone runner: execute every ``test_*`` function in ``namespace``.

    Returns a process exit code: ``0`` when nothing failed, ``1`` otherwise.
    Test functions take no arguments so that both pytest and this runner can
    call them identically (no pytest fixtures are used anywhere in ``tests/lab``).
    """
    tests = sorted(
        (name, value)
        for name, value in namespace.items()
        if name.startswith("test_") and callable(value)
    )
    if not tests:
        print("no test_* functions found in this module")
        return 1

    passed = skipped = 0
    failures: list[str] = []
    for name, func in tests:
        try:
            func()
        except SkipCheck as exc:
            skipped += 1
            print(f"SKIP  {name}: {exc}")
        except AssertionError as exc:
            failures.append(name)
            print(f"FAIL  {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - a crashing test is a failure
            failures.append(name)
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
            traceback.print_exc()
        else:
            passed += 1
            print(f"PASS  {name}")

    print(f"\n{passed} passed, {skipped} skipped, {len(failures)} failed ({len(tests)} collected)")
    if failures:
        print("failed: " + ", ".join(failures))
    return 1 if failures else 0
