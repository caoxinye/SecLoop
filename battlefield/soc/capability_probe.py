# SPDX-License-Identifier: Apache-2.0
"""Discover what a target can actually do — the source of ``T_A`` (paper Eq. 3).

The paper defines ``T_A`` as the tools available **in the current environment**. This
module is what makes that true rather than aspirational: it asks the blue-team VM which
OS it runs, whether ``sudo -n`` works, and which executables exist, and the answer decides
what the agent may offer the model.

Design rules
------------
* **One round trip.** ``uname``, the root check and every binary lookup run in a single
  ``vagrant ssh`` call; the probe script is generated from the catalogue by
  :func:`soc.tool_catalogue.detection_script`, so it cannot fall behind it.
* **Observed, never inferred.** A missing binary is *information* (the probe exits 0).
  A probe that cannot be interpreted at all is an *error* — this module raises rather
  than defaulting to a plausible-looking tool set, because a guessed ``T_A`` can
  advertise a Windows-only tool on a Linux prompt.
* **Pure parsing.** :func:`parse_probe_output` takes text and returns data, so the
  interpretation is unit-testable without a VM, a driver, or a network.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .tool_catalogue import (
    BINARY_MARKER,
    OS_MARKER,
    ROOT_MARKER,
    SOC_RENDERERS,
    detection_script,
    names_from_capabilities,
    renderer_for_os,
    unavailable_reasons,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CapabilityProbeError",
    "ParsedProbe",
    "TargetCapabilities",
    "capabilities_from_output",
    "parse_probe_output",
    "probe_capabilities",
]

#: Conservative budget: the script only runs builtins.
DEFAULT_PROBE_TIMEOUT_S = 30.0


class CapabilityProbeError(RuntimeError):
    """The target's capabilities could not be determined, so ``T_A`` cannot be built."""


@dataclass(frozen=True)
class ParsedProbe:
    """The raw facts a probe reported.

    Args:
        os_name: what ``uname -s`` printed (``unknown`` if it could not).
        root_available: whether ``sudo -n true`` succeeded.
        binaries: executables found by ``command -v``.
        reported_os: whether the OS marker was seen at all — without it the interpreter
            never ran our script, which is a failure and not an empty capability set.
    """

    os_name: str
    root_available: bool
    binaries: frozenset[str]
    reported_os: bool

    @property
    def renderer(self) -> str:
        return renderer_for_os(self.os_name, default="posix")


@dataclass(frozen=True)
class TargetCapabilities:
    """What one target can do, and therefore which tools may be offered.

    Args:
        vm: the VM the probe ran against.
        os_name: ``uname -s`` output.
        renderer: ``posix`` or ``powershell``, derived from ``os_name``.
        binaries: executables the target has, restricted to what the catalogue looks for.
        root_available: whether ``sudo -n`` works on the target.
        available_tools: the catalogue entries whose requirements are met, in §6 order.
        unavailable: ``name -> reasons``, so a refusal can explain itself.
        probe_command: the exact script that produced this, for the record.
        detail: truncated raw output, for debugging.
    """

    vm: str
    os_name: str
    renderer: str
    binaries: frozenset[str]
    root_available: bool
    available_tools: tuple[str, ...]
    unavailable: dict[str, tuple[str, ...]] = field(default_factory=dict)
    probe_command: str = ""
    detail: str = ""

    def offered(self) -> tuple[str, ...]:
        """Alias for :attr:`available_tools` (reads better at call sites)."""
        return self.available_tools

    def as_dict(self) -> dict[str, Any]:
        """JSON-serialisable form (``GET /capabilities``)."""
        available = set(self.available_tools)
        return {
            "vm": self.vm,
            "os": self.os_name,
            "renderer": self.renderer,
            "root_available": self.root_available,
            "binaries": sorted(self.binaries),
            "available_tools": list(self.available_tools),
            "unavailable": {
                name: list(reasons)
                for name, reasons in sorted(self.unavailable.items())
                if name not in available
            },
            "probe_command": self.probe_command,
            "detail": self.detail,
        }


def parse_probe_output(stdout: str) -> ParsedProbe:
    """Read the probe's markers out of ``stdout`` (pure function).

    Unknown lines are ignored: the guest may print motd/banner noise around the script.
    """
    os_name = "unknown"
    root = False
    binaries: set[str] = set()
    saw_os = False

    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if line.startswith(OS_MARKER):
            os_name = line[len(OS_MARKER) :].strip() or "unknown"
            saw_os = True
        elif line.startswith(ROOT_MARKER):
            root = line[len(ROOT_MARKER) :].strip() == "1"
        elif line.startswith(BINARY_MARKER):
            name = line[len(BINARY_MARKER) :].strip()
            if name:
                binaries.add(name)

    return ParsedProbe(
        os_name=os_name,
        root_available=root,
        binaries=frozenset(binaries),
        reported_os=saw_os,
    )


def capabilities_from_output(
    stdout: str,
    *,
    vm: str,
    returncode: int = 0,
    error: str | None = None,
    timed_out: bool = False,
    probe_command: str = "",
    max_detail_chars: int = 500,
) -> TargetCapabilities:
    """Build :class:`TargetCapabilities` from one probe run.

    Raises:
        CapabilityProbeError: the probe did not complete, or did not report an OS. Refusing
            to answer is the point: an unusable probe means ``T_A`` cannot be trusted, and
            silently returning an empty (or full) tool set would be a guess.
    """
    parsed = parse_probe_output(stdout)
    detail = (stdout or "").strip()[:max_detail_chars]

    if timed_out:
        raise CapabilityProbeError(
            f"capability probe on {vm!r} timed out, so it had not finished looking for "
            f"requirements. Partial output: {detail or '<empty>'}"
        )
    if returncode != 0:
        raise CapabilityProbeError(
            f"capability probe on {vm!r} exited {returncode} ({error or 'no error text'}); a "
            f"probe that did not complete cannot describe the environment, even though it "
            f"printed {len(parsed.binaries)} marker(s). Output: {detail or '<empty>'}"
        )
    if not parsed.reported_os:
        raise CapabilityProbeError(
            f"capability probe on {vm!r} produced no {OS_MARKER} line, so the target's OS "
            f"is unknown and T_A cannot be built honestly. Raw output: {detail or '<empty>'}"
        )

    renderer = parsed.renderer
    if renderer not in SOC_RENDERERS:
        logger.warning(
            "capability probe on %s reports a %s session; this SOC only drives %s, so no "
            "tool will be offered",
            vm,
            renderer,
            sorted(SOC_RENDERERS),
        )

    available = names_from_capabilities(
        renderer=renderer,
        binaries=parsed.binaries,
        root_available=parsed.root_available,
    )
    return TargetCapabilities(
        vm=vm,
        os_name=parsed.os_name,
        renderer=renderer,
        binaries=parsed.binaries,
        root_available=parsed.root_available,
        available_tools=available,
        unavailable=unavailable_reasons(
            renderer=renderer,
            binaries=parsed.binaries,
            root_available=parsed.root_available,
        ),
        probe_command=probe_command or detection_script(),
        detail=detail,
    )


def probe_capabilities(
    driver: Any,
    vm: str,
    *,
    timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
) -> TargetCapabilities:
    """Probe ``vm`` through ``driver`` (a ``VagrantDriver`` or a fake).

    Raises:
        CapabilityProbeError: the SSH call failed or its output was unusable.
    """
    command = detection_script()
    result = driver.ssh(vm, command, timeout_s=timeout_s)
    return capabilities_from_output(
        getattr(result, "stdout", "") or "",
        vm=vm,
        returncode=int(getattr(result, "returncode", 0)),
        error=getattr(result, "error", None),
        timed_out=bool(getattr(result, "timed_out", False)),
        probe_command=command,
    )
