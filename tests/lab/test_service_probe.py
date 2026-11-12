# SPDX-License-Identifier: Apache-2.0
"""How ``rs_service`` is decided (paper Eq. 12).

``target/README.md`` states that ``index.php`` "must stay byte-exact: the feedback
stage decides ``rs_service`` from a real HTTP probe of that URL".  The marker is
required by default (``strict_marker=True``) for that reason: otherwise a bare HTTP 200
from anything -- a proxy, a captive portal, a page somebody replaced -- counts as a
healthy service, against this module's own rule that "anything that cannot be verified
counts as 0".

No network is used: the HTTP side is a fake session, and the attacker-reachability
side is pointed at a closed local port (only ``target_http`` is asserted on).

Standard library only, and pytest-free so ``python tests/lab/test_service_probe.py``
works too.
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _labkit  # noqa: E402  (path bootstrap must come first)
from _labkit import REPO_ROOT, run_module_tests  # noqa: E402

sys.path.insert(0, str(REPO_ROOT))

from battlefield.soc.service_probe import (  # noqa: E402
    DEFAULT_STRICT_MARKER,
    DEFAULT_TARGET_MARKER,
    TARGET_MARKER_STRICT_ENV,
    ServiceProbe,
    probe_service,
)


class FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


class FakeSession:
    """Minimal stand-in for ``requests`` / a ``requests.Session``."""

    def __init__(self, status_code: int = 200, text: str = "") -> None:
        self.response = FakeResponse(status_code, text)
        self.calls = 0

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls += 1
        return self.response


@contextlib.contextmanager
def env(name: str, value: str | None):
    previous = os.environ.get(name)
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def make_probe(session: FakeSession | None = None, **kwargs: object) -> ServiceProbe:
    """A probe whose attacker check hits a closed local port instead of the lab.

    ``timeout_s`` is tiny so the refused connection settles immediately; the HTTP side
    is a fake session and ignores it.
    """
    kwargs.setdefault("timeout_s", 0.05)
    return ServiceProbe(
        "http://127.0.0.1/index.php",
        red_host="127.0.0.1",
        red_port=1,
        session=session,
        **kwargs,
    )


# ---------------------------------------------------------------------------------------
# Configuration resolution
# ---------------------------------------------------------------------------------------
def test_the_marker_is_required_by_default() -> None:
    assert DEFAULT_STRICT_MARKER is True
    assert make_probe().strict_marker is True


def test_an_explicit_flag_overrides_both_ways() -> None:
    assert make_probe(strict_marker=False).strict_marker is False
    assert make_probe(strict_marker=True).strict_marker is True


def test_the_environment_variable_can_relax_and_tighten() -> None:
    for raw, expected in (
        ("0", False),
        ("false", False),
        ("no", False),
        ("1", True),
        ("yes", True),
        ("  ", True),  # blank means "unset", so the module default applies
        (None, True),
    ):
        with env(TARGET_MARKER_STRICT_ENV, raw):
            assert ServiceProbe.from_env().strict_marker is expected, f"{raw!r}"


# ---------------------------------------------------------------------------------------
# What the flag means
# ---------------------------------------------------------------------------------------
def test_the_shipped_marker_passes() -> None:
    result = make_probe(FakeSession(200, f"{DEFAULT_TARGET_MARKER}\n")).run()
    assert result.status_code == 200
    assert result.marker_ok is True
    assert result.target_http is True


def test_a_bare_200_without_the_marker_is_not_a_healthy_service_by_default() -> None:
    """A bare 200 without the marker is not this target's service."""
    result = make_probe(FakeSession(200, "<html>some other page</html>")).run()
    assert result.status_code == 200
    assert result.marker_ok is False
    assert result.target_http is False, (
        "a 200 from an unrecognised page must not count as this target's service "
        "being available (Eq. 12 is never inferred)"
    )


def test_relaxing_the_marker_accepts_a_bare_200() -> None:
    result = make_probe(
        FakeSession(200, "<html>some other page</html>"), strict_marker=False
    ).run()
    assert result.marker_ok is False
    assert result.target_http is True


def test_a_non_200_is_never_a_healthy_service() -> None:
    for strict in (True, False):
        result = make_probe(FakeSession(503, DEFAULT_TARGET_MARKER), strict_marker=strict).run()
        assert result.target_http is False, f"strict_marker={strict}"


def test_the_wrapper_function_uses_the_same_default() -> None:
    result = probe_service(
        "http://127.0.0.1/index.php",
        red_host="127.0.0.1",
        red_port=1,
        session=FakeSession(200, "unrelated"),
    )
    assert result.target_http is False


def test_marker_checking_can_be_disabled_with_an_empty_marker() -> None:
    """``expected_marker=''`` means "do not check a marker at all"."""
    result = make_probe(FakeSession(200, "unrelated"), expected_marker="").run()
    assert result.marker_ok is None
    assert result.target_http is True


if __name__ == "__main__":
    raise SystemExit(run_module_tests(dict(globals())))
