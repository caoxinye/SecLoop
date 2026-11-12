# SPDX-License-Identifier: Apache-2.0
"""Real service probe for ``rs_service`` (paper Eq. 12, ``docs/INTERFACES.md`` §4).

Eq. (12) is ``rs_service(S_i) = f_service(E_BVM, E_RVM, S_i) in {0, 1}``: the
service must still be available in **both** environments.  This module performs
the two measurements it needs, and nothing else:

1. an HTTP ``GET`` on the target application (default
   ``http://192.168.57.200/index.php``) which must answer ``200`` -- the lab's
   liveness anchor ``target/webapp/index.php``;
2. a real TCP reachability check on the attacker VM (default
   ``192.168.57.199:22``), proving the red environment is alive.

A heuristic -- "some blue
command succeeded and the attack score is below 0.5, so return 1.0 else 0.5" -- would
never touch a socket and could return ``0.5``, which is not in ``{0, 1}``.
There is no heuristic path here: if a probe cannot be completed the
result is ``False``/``0``, and the failure is reported.

``requests`` is preferred but optional: the probe falls back to
``urllib.request`` so the SOC package stays importable in a bare environment.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

logger = logging.getLogger(__name__)

try:  # pragma: no cover - depends on the environment
    import requests  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

__all__ = [
    "DEFAULT_RED_PROBE",
    "DEFAULT_STRICT_MARKER",
    "DEFAULT_TARGET_MARKER",
    "DEFAULT_TARGET_URL",
    "ServiceProbe",
    "ServiceProbeResult",
    "probe_service",
]

TARGET_URL_ENV = "SOC_TARGET_URL"
TARGET_MARKER_ENV = "SOC_TARGET_MARKER"
TARGET_MARKER_STRICT_ENV = "SOC_TARGET_MARKER_STRICT"
RED_PROBE_ENV = "SOC_RED_PROBE"
PROBE_TIMEOUT_ENV = "SOC_PROBE_TIMEOUT_S"

#: `docs/INTERFACES.md` §1: liveness anchor of the lab target.
DEFAULT_TARGET_URL = "http://192.168.57.200/index.php"
#: `docs/INTERFACES.md` §11: `index.php` always returns this fixed string.
DEFAULT_TARGET_MARKER = "SecLoop target OK"
#: Whether the marker is *required* for ``target_http``.  Default **True**, because
#: this module's own rule is "anything that cannot be verified counts as 0": a bare
#: HTTP 200 can come from a captive portal, a proxy or a page someone replaced, and
#: Eq. 12 asks whether *this* target's service is available.  The shipped `index.php`
#: is byte-exact (`target/README.md`), so the strict check passes on the reference
#: lab.  A replaced target must either keep the anchor or set
#: ``SOC_TARGET_MARKER_STRICT=0``.
DEFAULT_STRICT_MARKER = True
DEFAULT_RED_PROBE = "192.168.57.199:22"
DEFAULT_PROBE_TIMEOUT_S = 5.0
MAX_DETAIL_CHARS = 300


def _truthy(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _optional_truthy(value: str | None) -> bool | None:
    """``None`` when unset or blank, otherwise a boolean reading of ``value``.

    Used where a module default exists and the environment variable is an *override*:
    ``SOC_TARGET_MARKER_STRICT=0`` has to be able to switch strict mode **off**, which
    ``_truthy`` alone cannot express.
    """
    if value is None or not value.strip():
        return None
    return _truthy(value)


def parse_red_probe(value: str, *, default_port: int = 22) -> tuple[str, int]:
    """Parse ``host:port`` (a bare host gets ``default_port``)."""
    text = (value or "").strip()
    if not text:
        raise ValueError("empty attacker probe target")
    if text.startswith("[") and "]" in text:  # bracketed IPv6
        host, _, rest = text[1:].partition("]")
        return host, int(rest.lstrip(":") or default_port)
    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        if port_text.strip():
            return host.strip(), int(port_text)
        return host.strip(), default_port
    return text, default_port


@dataclass(frozen=True)
class ServiceProbeResult:
    """Outcome of one service probe round."""

    target_http: bool
    attacker_reachable: bool
    target_url: str = ""
    red_probe: str = ""
    status_code: int | None = None
    marker_ok: bool | None = None
    detail: str = ""
    timings_ms: dict[str, float] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """True only when both halves of Eq. (12) were verified."""
        return bool(self.target_http and self.attacker_reachable)

    def as_feedback(self) -> dict[str, bool]:
        """The exact ``feedback.service_probe`` shape of ``docs/INTERFACES.md`` §3.1."""
        return {
            "target_http": bool(self.target_http),
            "attacker_reachable": bool(self.attacker_reachable),
        }

    def to_dict(self) -> dict[str, Any]:
        """Diagnostic dump (logging only; never sent as the feedback field)."""
        payload = dataclasses.asdict(self)
        payload["ok"] = self.ok
        return payload


class ServiceProbe:
    """Performs the two real checks behind ``rs_service``.

    Args:
        target_url: HTTP liveness anchor of the target application.
        red_host: attacker VM host used for the reachability check.
        red_port: attacker VM port (SSH by default).
        timeout_s: per-check timeout in seconds.
        expected_marker: substring expected in the target's body (a wrong or missing
            marker makes ``target_http`` False unless ``strict_marker`` is off).
        strict_marker: ``None`` (default) uses :data:`DEFAULT_STRICT_MARKER` (True).
            An explicit ``True``/``False`` always wins, so the environment variable can
            both tighten and relax the check.
    """

    def __init__(
        self,
        target_url: str = DEFAULT_TARGET_URL,
        red_host: str = "192.168.57.199",
        red_port: int = 22,
        *,
        timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
        expected_marker: str = DEFAULT_TARGET_MARKER,
        strict_marker: bool | None = None,
        session: Any = None,
    ) -> None:
        self.target_url = target_url
        self.red_host = red_host
        self.red_port = int(red_port)
        self.timeout_s = float(timeout_s)
        self.expected_marker = expected_marker
        self.strict_marker = (
            DEFAULT_STRICT_MARKER if strict_marker is None else bool(strict_marker)
        )
        self._session = session

    @classmethod
    def from_env(cls) -> ServiceProbe:
        """Build the probe from ``SOC_*`` environment variables with lab defaults."""
        raw_red = os.getenv(RED_PROBE_ENV, DEFAULT_RED_PROBE)
        try:
            red_host, red_port = parse_red_probe(raw_red)
        except (ValueError, TypeError) as exc:
            logger.warning(
                "%s=%r is not a usable host:port (%s); falling back to %s",
                RED_PROBE_ENV,
                raw_red,
                exc,
                DEFAULT_RED_PROBE,
            )
            red_host, red_port = parse_red_probe(DEFAULT_RED_PROBE)
        return cls(
            target_url=os.getenv(TARGET_URL_ENV, DEFAULT_TARGET_URL),
            red_host=red_host,
            red_port=red_port,
            timeout_s=float(os.getenv(PROBE_TIMEOUT_ENV, DEFAULT_PROBE_TIMEOUT_S)),
            expected_marker=os.getenv(TARGET_MARKER_ENV, DEFAULT_TARGET_MARKER),
            strict_marker=_optional_truthy(os.getenv(TARGET_MARKER_STRICT_ENV)),
        )

    @property
    def red_probe(self) -> str:
        """``host:port`` label used in logs and the diagnostic dump."""
        return f"{self.red_host}:{self.red_port}"

    # ---------------------------------------------------------------- probes

    def run(self) -> ServiceProbeResult:
        """Perform both checks and return the (never-heuristic) result."""
        timings: dict[str, float] = {}
        status_code, marker_ok, http_detail = self._probe_target_http(timings)
        attacker_reachable, tcp_detail = self._probe_attacker(timings)
        detail = f"{http_detail}; {tcp_detail}"
        target_http = self._target_is_available(status_code, marker_ok)
        logger.info(
            "probe: target_http=%s attacker_reachable=%s (%s)",
            target_http,
            attacker_reachable,
            detail,
        )
        return ServiceProbeResult(
            target_http=target_http,
            attacker_reachable=attacker_reachable,
            target_url=self.target_url,
            red_probe=self.red_probe,
            status_code=status_code,
            marker_ok=marker_ok,
            detail=detail[:MAX_DETAIL_CHARS],
            timings_ms=timings,
        )

    def _target_is_available(self, status_code: int | None, marker_ok: bool | None) -> bool:
        """HTTP 200 **and** the marker rule satisfied.

        ``marker_ok is None`` means no marker was configured, i.e. there is nothing to
        verify -- so it must not count as a *failed* check.  Without that case, setting
        ``expected_marker=""`` to skip marker checking would report the service as down,
        which is the opposite of what the caller asked for.
        """
        if status_code != 200:
            return False
        if marker_ok is False and self.strict_marker:
            return False
        return True

    def _probe_target_http(
        self, timings: dict[str, float]
    ) -> tuple[int | None, bool | None, str]:
        """``GET target_url``; returns ``(status_code, marker_ok, detail)``."""
        started = time.monotonic()
        status_code: int | None = None
        body = ""
        error_text: str | None = None
        try:
            if requests is not None:
                session = self._session or requests
                response = session.get(self.target_url, timeout=self.timeout_s, allow_redirects=True)
                status_code = int(response.status_code)
                body = response.text or ""
            else:  # pragma: no cover - only when requests is absent
                with urlrequest.urlopen(self.target_url, timeout=self.timeout_s) as response:  # noqa: S310
                    status_code = int(response.status)
                    body = response.read().decode("utf-8", errors="replace")
        except urlerror.HTTPError as exc:
            status_code = int(exc.code)
            error_text = f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001 - requests raises several families
            error_text = f"{type(exc).__name__}: {exc}"
        timings["target_http_ms"] = round((time.monotonic() - started) * 1000, 1)

        marker_ok: bool | None = None
        if self.expected_marker:
            marker_ok = self.expected_marker in body
            if status_code == 200 and not marker_ok:
                logger.warning(
                    "probe: %s answered %s but does not contain the expected marker %r "
                    "(first 120 bytes: %r); check that target/webapp is deployed",
                    self.target_url,
                    status_code,
                    self.expected_marker,
                    body[:120],
                )
        if error_text:
            return status_code, marker_ok, f"target GET {self.target_url} failed ({error_text})"
        marker_note = (
            "marker ok"
            if marker_ok
            else ("marker missing" if marker_ok is False else "no marker configured")
        )
        return (
            status_code,
            marker_ok,
            f"target GET {self.target_url} -> {status_code} ({marker_note}, "
            f"{timings['target_http_ms']:.0f}ms)",
        )

    def _probe_attacker(self, timings: dict[str, float]) -> tuple[bool, str]:
        """TCP-connect to the attacker VM; returns ``(reachable, detail)``."""
        started = time.monotonic()
        try:
            with socket.create_connection((self.red_host, self.red_port), timeout=self.timeout_s):
                reachable = True
            error_text = ""
        except OSError as exc:
            reachable = False
            error_text = f"{type(exc).__name__}: {exc}"
        timings["attacker_tcp_ms"] = round((time.monotonic() - started) * 1000, 1)
        if reachable:
            return True, f"attacker {self.red_probe} reachable ({timings['attacker_tcp_ms']:.0f}ms)"
        return False, f"attacker {self.red_probe} unreachable ({error_text})"


def probe_service(
    target_url: str = DEFAULT_TARGET_URL,
    red_host: str = "192.168.57.199",
    red_port: int = 22,
    *,
    timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
    expected_marker: str = DEFAULT_TARGET_MARKER,
    strict_marker: bool | None = None,
    session: Any = None,
) -> ServiceProbeResult:
    """Convenience wrapper: run one probe and return its :class:`ServiceProbeResult`."""
    return ServiceProbe(
        target_url=target_url,
        red_host=red_host,
        red_port=red_port,
        timeout_s=timeout_s,
        expected_marker=expected_marker,
        strict_marker=strict_marker,
        session=session,
    ).run()
