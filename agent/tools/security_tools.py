# SPDX-License-Identifier: Apache-2.0
"""The SecLoop security-response tools (INTERFACES §6).

**The tool table lives in one place**: :mod:`battlefield.soc.tool_catalogue`. This module
does not define tools — it *binds implementations* to catalogue entries. That split is
deliberate:

* the catalogue (owned by the executing side) says what a tool is called, what it
  declares, what command it runs, whether it needs root, and what it requires the
  environment to have — paper Eq. 3 defines ``T_A`` as the tools available **in the current
  environment**, so availability is *probed* (``GET /capabilities``), never stored;
* this module supplies the client-side ``func`` and the domain validator for each entry,
  and fails loudly at import if the two sets are not 1:1.

There is no second, hand-written table with its own ``command`` strings; the
catalogue's docstring explains why one table is the only one.

``TOOL_SPECS`` is the **full** catalogue (host-independent) so that name-membership
checks — the training reward's registry validation, for instance — do not change with the
host. What varies per environment is what is *offered*:
:func:`create_security_tools` registers only the entries the environment was **found** to
support, so ``T_A``, the LLM's allowed-tool set and ``environment["tools"]`` cannot
disagree. That is why the agent passes ``available=`` from the SOC's probe; a manager
built without one knows nothing about any machine and says so.

Execution model: every tool is deployed by the SOC (``POST /execute_ability``), which is
the only component allowed to build the shell command.  A tool function therefore sends
``{"tool": ..., "params": {...}}`` and returns the SOC's **full feedback vector**
(``rs_exe`` / ``rs_attack`` / ``rs_service`` / ``F_i``), not a bare scalar score: a client
that discards the three-dimensional feedback leaves the agent with nothing to reason about.
"""

from __future__ import annotations

import ipaddress
import logging
import sys
from pathlib import Path
from typing import Any, Sequence

from .batch_executor import BatchExecutor
from .tool_manager import (
    ParameterSpec,
    StrategyValidationError,
    Tool,
    ToolManager,
)

# `battlefield` is a namespace package at the repository root, so this module can be
# imported from any working directory without pulling in the SOC package's eager imports.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:  # pragma: no cover - depends on the launch directory
    sys.path.insert(0, str(_REPO_ROOT))

from battlefield.soc.tool_catalogue import (  # noqa: E402  (import after the path shim)
    TOOL_CATALOGUE,
    catalogue_members,
    render_tool_descriptions,
    spec_for,
)

logger = logging.getLogger(__name__)

__all__ = [
    "TOOL_SPECS",
    "TOOL_NAMES",
    "ParameterSpec",
    "StrategyValidationError",
    "Tool",
    "ToolManager",
    "bash",
    "block_ip",
    "create_security_tools",
    "get_tool_descriptions",
    "powershell",
    "render_tool_descriptions",
]

#: INTERFACES §6 command for ``block_ip``, derived from the catalogue instead of
#: restated (it is the SOC that runs it; this is for the log line).
BLOCK_IP_COMMAND = spec_for("block_ip").template


def _resolve_executor(executor: BatchExecutor | None) -> BatchExecutor:
    return executor if executor is not None else BatchExecutor()


def _require_ipv4(value: Any) -> str:
    """Validate the §6 ``ip`` parameter (an IPv4 literal).

    Raises:
        StrategyValidationError: blank or not a valid IPv4 address.
    """
    text = "" if value is None else str(value).strip()
    if not text:
        raise StrategyValidationError("block_ip requires a non-empty IPv4 address (INTERFACES §6)")
    try:
        return str(ipaddress.IPv4Address(text))
    except ipaddress.AddressValueError as exc:
        raise StrategyValidationError(
            f"block_ip: {text!r} is not an IPv4 address (INTERFACES §6 expects '{{\"ip\": \"<IPv4>\"}}')"
        ) from exc


# --------------------------------------------------------------------------------------
# Tool implementations (each one is a single SOC request for a single tool)
# --------------------------------------------------------------------------------------
def _validate_block_ip_params(params: dict[str, Any]) -> dict[str, Any]:
    """Registry-level domain check for ``block_ip``: normalise ``ip`` to a canonical IPv4."""
    return {"ip": _require_ipv4(params.get("ip"))}


def block_ip(ip: str, *, executor: BatchExecutor | None = None) -> dict[str, Any]:
    """Block one malicious IPv4 address on the blue-team target.

    Args:
        ip: IPv4 literal, e.g. ``192.168.57.199``.
        executor: SOC transport override (mainly for tests).

    Returns:
        The SOC tool result enriched with the full feedback vector.

    Raises:
        StrategyValidationError: ``ip`` is missing or not an IPv4 literal.
    """
    address = _require_ipv4(ip)
    logger.info(
        "block_ip: the SOC will run `%s` on the blue-team target",
        BLOCK_IP_COMMAND.format(ip=address),
    )
    return _resolve_executor(executor).execute_tool("block_ip", {"ip": address})


def bash(command: str, *, executor: BatchExecutor | None = None) -> dict[str, Any]:
    """Execute a shell command on the blue-team target.

    Raises:
        StrategyValidationError: ``command`` is missing or blank.
    """
    text = "" if command is None else str(command)
    if not text.strip():
        raise StrategyValidationError("bash requires a non-empty 'command' (INTERFACES §6)")
    logger.info("bash: deploying a shell command on the blue-team target")
    return _resolve_executor(executor).execute_tool("bash", {"command": text})


def powershell(command: str, *, executor: BatchExecutor | None = None) -> dict[str, Any]:
    """Execute a PowerShell command (kept for Windows targets; unused for the sqli lab).

    Raises:
        StrategyValidationError: ``command`` is missing or blank.
    """
    text = "" if command is None else str(command)
    if not text.strip():
        raise StrategyValidationError("powershell requires a non-empty 'command' (INTERFACES §6)")
    logger.info("powershell: deploying a PowerShell command on the blue-team target")
    return _resolve_executor(executor).execute_tool("powershell", {"command": text})


# --------------------------------------------------------------------------------------
# Registry: the catalogue plus this client's bindings (one table, no duplication)
# --------------------------------------------------------------------------------------
#: ``name -> (func, validator)``. Every catalogue entry needs exactly one binding; the
#: check below turns a missing or stray binding into an import-time error instead of a
#: lower ``rs_exe`` at run time.
_IMPLEMENTATIONS: dict[str, tuple[Any, Any]] = {
    "block_ip": (block_ip, _validate_block_ip_params),
    "bash": (bash, None),
    "powershell": (powershell, None),
}

_missing = sorted(set(spec.name for spec in TOOL_CATALOGUE) - set(_IMPLEMENTATIONS))
_stray = sorted(set(_IMPLEMENTATIONS) - set(spec.name for spec in TOOL_CATALOGUE))
if _missing or _stray:
    raise RuntimeError(
        "the tool catalogue and the agent's implementations disagree: "
        f"catalogue entries without an implementation: {_missing}; "
        f"implementations without a catalogue entry: {_stray}"
    )

#: The declarative catalogue in §6 order, platform-independent.
TOOL_SPECS: tuple[Tool, ...] = tuple(
    Tool(
        spec.name,
        spec.description,
        tuple(ParameterSpec(p.name, p.type, p.required) for p in spec.parameters),
        command=spec.documented_command(),
        func=_IMPLEMENTATIONS[spec.name][0],
        validator=_IMPLEMENTATIONS[spec.name][1],
    )
    for spec in TOOL_CATALOGUE
)

#: Tool names in §6 order (the full catalogue).
TOOL_NAMES: tuple[str, ...] = tuple(tool.name for tool in TOOL_SPECS)


def create_security_tools(
    *, executor: BatchExecutor | None = None, available: Sequence[str] | None = None
) -> ToolManager:
    """Build a :class:`ToolManager` from the tools **discovered on the target**.

    Args:
        executor: SOC transport override (mainly for tests).
        available: the tool names the SOC probed out of the blue-team VM
            (``GET /capabilities``). This is the ``T_A`` set of paper Eq. 3 — "the tools
            available in the current environment" — and only these are registered, so a
            caller cannot offer or accept a tool the environment cannot run.
            When ``None`` the **full catalogue** is registered, which is what the
            training/reward path wants for name-membership checks; a WARNING is logged
            because a manager built without a probe describes no real environment.

    Construction is offline: nothing is read from the dataset and no request is sent
    (the SOC endpoint and VM pair are resolved lazily on the first execution).
    """
    if available is None:
        logger.warning(
            "create_security_tools() called without probed capabilities; registering the "
            "full catalogue for name-membership checks only. Availability is defined by "
            "the environment (paper Eq.3), so anything that renders T_A or E must pass the "
            "tools that environment was found to have."
        )
        chosen = TOOL_SPECS
    else:
        wanted = set(catalogue_members(list(available)))
        chosen = tuple(tool for tool in TOOL_SPECS if tool.name in wanted)
        if not chosen:
            raise StrategyValidationError(
                f"the probed environment offers no usable tool (discovered: "
                f"{sorted(wanted) or 'none'}); refusing to build a prompt with an empty T_A"
            )
    return ToolManager(chosen, executor=executor)


def get_tool_descriptions(available: Sequence[str] | None = None) -> str:
    """The ``T_A`` text (INTERFACES §6 / paper Eq. 3).

    ``available`` are the discovered tool names; with ``None`` the full catalogue is
    rendered (see :func:`create_security_tools` for why that path exists).
    """
    if available is None:
        return render_tool_descriptions(TOOL_SPECS)
    wanted = set(catalogue_members(list(available)))
    return render_tool_descriptions(tool for tool in TOOL_SPECS if tool.name in wanted)
