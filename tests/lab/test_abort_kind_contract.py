# SPDX-License-Identifier: Apache-2.0
"""The `abort_kind` contract: "the attack never ran" must be *classified*, not inferred.

Why this file exists
--------------------
A fatal probe abort and a perfect block produce **the same bytes** on the wire: a valid
`[RESULT]` line whose every stage is `false`. The RTC cannot tell "the defence kept me
out" from "our own harness broke" without more information, and would credit both.

`abort_kind` (``docs/INTERFACES.md`` §2.1) is the producer's own statement of *why* it
stopped. Two rules make it trustworthy, and both are pinned here:

1. the producer and the consumer agree on the vocabulary -- the producer holds its own copy
   because it runs on the attacker VM and must stay self-contained, so the copies could
   drift;
2. **every** abort site in the producer carries a kind, and the default is `unclassified`.
   A raise site that forgets its kind would fall back to "we do not know", never to a
   flattering "the defence worked".

These tests are stdlib-only and need no lab, no VM and no network.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from battlefield.attacks import sqli_lab  # noqa: E402
from battlefield.soc.policy_execution_validator import ABORT_KINDS as PEV_KINDS  # noqa: E402

PRODUCER_KINDS = sqli_lab.ABORT_KINDS
PRODUCER_PATH = Path(sqli_lab.__file__)


# ---------------------------------------------------------------------------------------
# 1. The vocabulary
# ---------------------------------------------------------------------------------------
def test_the_two_copies_of_the_vocabulary_agree():
    """The producer cannot import the SOC package (it runs on the attacker VM), so the
    duplication is deliberate -- and this is what stops it drifting."""
    assert PRODUCER_KINDS == PEV_KINDS


def test_the_vocabulary_is_exactly_the_four_kinds_plus_unclassified():
    assert PRODUCER_KINDS == {
        "target-unreachable",
        "oracle-unconfirmed",
        "dependency-missing",
        "config-invalid",
        "unclassified",
    }


def test_unclassified_is_the_default_never_a_flattering_one():
    """An unclassified abort must mean "we do not know", not "the defence worked"."""
    exc = sqli_lab.ProbeError("boom")
    assert exc.kind == "unclassified"
    assert "unclassified" in PRODUCER_KINDS


def test_the_attacker_unreachable_kind_is_shared_with_the_consumer():
    """The one kind that counts as a block is a named constant on the consumer side."""
    from battlefield.soc.policy_execution_validator import TARGET_UNREACHABLE

    assert TARGET_UNREACHABLE == "target-unreachable"
    assert TARGET_UNREACHABLE in PEV_KINDS


# ---------------------------------------------------------------------------------------
# 2. Every abort site carries its kind (AST -- so a new raise cannot forget)
# ---------------------------------------------------------------------------------------
def _probe_error_raises(function_name: str) -> list[ast.Call]:
    """Every ``raise ProbeError(...)`` call inside ``function_name`` (any nesting)."""
    tree = ast.parse(PRODUCER_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == function_name:
                    return [
                        sub.exc
                        for sub in ast.walk(item)
                        if isinstance(sub, ast.Raise)
                        and isinstance(sub.exc, ast.Call)
                        and getattr(sub.exc.func, "id", None) == "ProbeError"
                    ]
    raise AssertionError(f"{function_name}() not found in {PRODUCER_PATH.name}")


def test_every_health_abort_is_classified_as_target_unreachable():
    calls = _probe_error_raises("check_health")
    assert len(calls) >= 3, "the three health failure modes (connect, status, marker) must all classify"
    for call in calls:
        kinds = [
            kw.value.value
            for kw in call.keywords
            if kw.arg == "kind" and isinstance(kw.value, ast.Constant)
        ]
        assert kinds == ["target-unreachable"], (
            f"line {call.lineno}: a health abort without kind='target-unreachable' would be "
            f"read as 'unclassified', i.e. unmeasured -- a block would silently lose its credit"
        )


def test_every_calibration_abort_is_classified_as_oracle_unconfirmed():
    calls = _probe_error_raises("calibrate")
    assert len(calls) >= 4, "all four calibration failure modes must classify"
    for call in calls:
        kinds = [
            kw.value.value
            for kw in call.keywords
            if kw.arg == "kind" and isinstance(kw.value, ast.Constant)
        ]
        assert kinds == ["oracle-unconfirmed"], (
            f"line {call.lineno}: an oracle abort must not claim the target was unreachable, "
            f"or a reachable-but-broken target would be credited as a block"
        )


def test_the_execute_path_does_not_raise_probe_error_at_all():
    """Per-stage failures are *measurements* (guarded), never fatal aborts.

    If `execute()` could raise ProbeError, a partially measured round would be discarded
    instead of reported -- so the guard is part of the contract, not an implementation
    detail.
    """
    assert _probe_error_raises("execute") == []


# ---------------------------------------------------------------------------------------
# 3. Behaviour: the payload carries the kind
# ---------------------------------------------------------------------------------------
def test_a_completed_run_reports_no_abort_kind():
    result = sqli_lab._build_result(
        target_ip="192.168.57.200",
        port=80,
        mode="time",
        delay=1.0,
        stages=sqli_lab._blank_stages(),
        extracted=sqli_lab._blank_extracted(),
        oracle_errors=0,
        requests_sent=7,
        elapsed_s=1.5,
        error=None,
        abort_kind=None,
    )
    assert result["abort_kind"] is None


def test_an_unknown_kind_is_coerced_to_unclassified():
    """The producer must never invent a kind the consumer does not know."""
    result = sqli_lab._build_result(
        target_ip="192.168.57.200",
        port=80,
        mode="time",
        delay=1.0,
        stages=sqli_lab._blank_stages(),
        extracted=sqli_lab._blank_extracted(),
        oracle_errors=0,
        requests_sent=0,
        elapsed_s=0.1,
        error="whatever",
        abort_kind="the-defence-did-it",  # not in the vocabulary
    )
    assert result["abort_kind"] == "unclassified"


def test_the_field_order_is_frozen_and_abort_kind_is_last():
    """`docs/INTERFACES.md` §2.1 freezes the order and documents ``abort_kind`` as the
    last field."""
    result = sqli_lab._build_result(
        target_ip="192.168.57.200",
        port=80,
        mode="time",
        delay=1.0,
        stages=sqli_lab._blank_stages(),
        extracted=sqli_lab._blank_extracted(),
        oracle_errors=0,
        requests_sent=0,
        elapsed_s=0.1,
        error=None,
        abort_kind=None,
    )
    assert list(result) == [
        "attack_mode", "target_ip", "target_port", "target_url", "mode", "delay_s",
        "score", "stages", "extracted", "oracle_errors", "requests", "elapsed_s",
        "error", "abort_kind",
    ]


# ---------------------------------------------------------------------------------------
# 4. Behaviour: real abort paths
# ---------------------------------------------------------------------------------------
class _Response:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class _Session:
    """A fake requests session. `exc` makes the request raise instead of answering."""

    def __init__(self, response=None, exc: Exception | None = None) -> None:
        self.response = response
        self.exc = exc

    def get(self, url: str, **kwargs) -> _Response:
        if self.exc is not None:
            raise self.exc
        return self.response


def _probe(session) -> "sqli_lab.SqliLabProbe":
    return sqli_lab.SqliLabProbe("192.168.57.200", 80, 1.0, 5.0, "time", session)


def test_a_connect_failure_is_target_unreachable():
    probe = _probe(_Session(exc=ConnectionError("connection refused")))
    try:
        probe.check_health()
    except sqli_lab.ProbeError as exc:
        assert exc.kind == "target-unreachable"
    else:
        raise AssertionError("check_health() should have raised")


def test_a_non_200_health_anchor_is_target_unreachable():
    probe = _probe(_Session(_Response(403, "forbidden")))
    try:
        probe.check_health()
    except sqli_lab.ProbeError as exc:
        assert exc.kind == "target-unreachable"
    else:
        raise AssertionError("check_health() should have raised")


def test_a_200_without_the_marker_is_target_unreachable():
    """A `200` from a proxy or a WAF is not the service; the marker rule is why."""
    probe = _probe(_Session(_Response(200, "<html>portal</html>")))
    try:
        probe.check_health()
    except sqli_lab.ProbeError as exc:
        assert exc.kind == "target-unreachable"
    else:
        raise AssertionError("check_health() should have raised")


def test_a_bad_invocation_reports_config_invalid_without_touching_the_network():
    """End to end through `main()`: an out-of-lab target is refused and *classified*.

    No network is used -- the refusal happens before any socket is opened -- so this test
    is safe on any machine, and it pins the whole producer-to-stdout path.
    """
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        exit_code = sqli_lab.main(["--target-ip", "8.8.8.8", "--port", "80"])
    assert exit_code == 0, "the script always exits 0; the verdict is in the payload"

    lines = [line for line in buffer.getvalue().splitlines() if line.startswith("[RESULT] ")]
    assert len(lines) == 1, f"exactly one [RESULT] line is required, got {lines!r}"
    payload = json.loads(lines[0][len("[RESULT] "):])
    assert payload["abort_kind"] == "config-invalid"
    assert payload["score"] == 0.0
    assert payload["requests"] == 0, "the refusal must not have opened a connection"
    assert all(stage["success"] is False for stage in payload["stages"])


def test_the_attacker_script_never_imports_the_soc_package():
    """It ships to the red VM, which has no repository checkout -- so the duplication of
    the vocabulary (checked above) is a hard requirement, not a convenience."""
    source = PRODUCER_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    assert not any(mod.startswith("battlefield") or mod.startswith("agent") for mod in modules), (
        f"the attacker script must stay standalone, but it imports {modules!r}"
    )


def test_the_producer_module_is_importable_without_requests():
    """`requests` is optional on the attacker VM: the import must degrade, not explode."""
    source = PRODUCER_PATH.read_text(encoding="utf-8")
    assert "requests = None" in source, "the soft-import fallback disappeared"
    # And the module really is loaded from this repository (not a stale site-packages copy).
    assert Path(importlib.util.find_spec("battlefield.attacks.sqli_lab").origin).resolve() == (
        PRODUCER_PATH.resolve()
    )
