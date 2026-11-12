# SPDX-License-Identifier: Apache-2.0
"""Tool registry and strategy executor for the SecLoop agent (INTERFACES §6).

``get_tool_descriptions()`` renders the ``T_A`` section of the prompt (paper Eq.3) in the
exact frozen format::

    - block_ip: Block an IP address using iptables. Parameters: ip (string, required)

The registry itself lives in :mod:`agent.tools.security_tools` (the cross-subsystem single
source of truth, re-exported by ``training/src/open_r1/utils/security_tools.py``); this
module only provides the generic ``Tool`` / ``ToolManager`` machinery and the executor.

A strategy is always submitted as **one** SOC request: :meth:`ToolManager.execute_strategy`
validates the whole list and hands it to :class:`~agent.tools.batch_executor.BatchExecutor`,
which performs a single ``POST /execute_ability``.  Nothing here fans a strategy out into
per-tool requests.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .batch_executor import BatchExecutor, VMConfig

logger = logging.getLogger(__name__)

_JSON_TYPES = ("string", "integer", "number", "boolean", "object", "array")


class StrategyValidationError(ValueError):
    """A generated strategy (or a single tool call) violates the INTERFACES §6 contract."""


@dataclass(frozen=True)
class ParameterSpec:
    """One declared parameter of a tool, as it appears in ``T_A``."""

    name: str
    type: str = "string"
    required: bool = True

    def render(self) -> str:
        """``ip (string, required)`` — the §6 ``T_A`` fragment."""
        requirement = "required" if self.required else "optional"
        return f"{self.name} ({self.type}, {requirement})"

    def check(self, value: Any) -> str | None:
        """Return an error message when ``value`` violates this specification."""
        kind = self.type
        if kind == "string":
            if not isinstance(value, str):
                return f"expected a string, got {type(value).__name__}"
            if self.required and not value.strip():
                return "must not be empty"
        elif kind == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                return f"expected an integer, got {type(value).__name__}"
        elif kind == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return f"expected a number, got {type(value).__name__}"
        elif kind == "boolean":
            if not isinstance(value, bool):
                return f"expected a boolean, got {type(value).__name__}"
        elif kind == "object":
            if not isinstance(value, Mapping):
                return f"expected an object, got {type(value).__name__}"
        elif kind == "array":
            if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
                return f"expected an array, got {type(value).__name__}"
        return None


class Tool:
    """A registered security-response tool.

    Args:
        name: canonical tool name (INTERFACES §6).
        description: one-sentence description used verbatim in ``T_A``.
        parameters: declared parameters in order.
        command: documentation of what the SOC executes for this tool (§6 "执行的命令").
            The command is built by the SOC, not by this client.
        func: implementation, called as ``func(**params, executor=<BatchExecutor>)``.
        validator: optional domain check applied to the type-checked params; it receives a
            mapping and returns the (possibly normalised) mapping, raising ``ValueError``
            when the values are not usable.  This is what makes ``validate_strategy``
            reject e.g. ``{"ip": "not-an-ip"}`` *before* anything is sent to the SOC.
    """

    def __init__(
        self,
        name: str,
        description: str,
        parameters: Sequence[ParameterSpec] = (),
        *,
        command: str = "",
        func: Callable[..., dict[str, Any]] | None = None,
        validator: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    ) -> None:
        if not str(name).strip():
            raise ValueError("a Tool needs a non-empty name")
        self.name = str(name).strip()
        self.description = str(description).strip()
        self.parameters: tuple[ParameterSpec, ...] = tuple(parameters)
        self.command = str(command).strip()
        self.func = func
        self.validator = validator

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        params = ", ".join(spec.name for spec in self.parameters)
        return f"Tool({self.name!r}, params=({params}))"

    def parameter(self, name: str) -> ParameterSpec | None:
        for spec in self.parameters:
            if spec.name == name:
                return spec
        return None

    def check_params(self, params: Mapping[str, Any]) -> dict[str, Any]:
        """Validate and normalise ``params`` for this tool.

        Raises:
            StrategyValidationError: unknown parameter, missing required parameter, or a
                value of the wrong JSON type.
        """
        if not isinstance(params, Mapping):
            raise StrategyValidationError(
                f"tool '{self.name}': params must be an object, got {type(params).__name__}"
            )
        known = {spec.name: spec for spec in self.parameters}
        unknown = [key for key in params if key not in known]
        if unknown:
            raise StrategyValidationError(
                f"tool '{self.name}' does not accept {sorted(unknown)}; accepted: {sorted(known)}"
            )
        normalised: dict[str, Any] = {}
        for spec in self.parameters:
            if spec.name not in params or params[spec.name] is None:
                if spec.required:
                    raise StrategyValidationError(
                        f"tool '{self.name}' is missing the required parameter '{spec.name}' "
                        f"({spec.render()})"
                    )
                continue
            problem = spec.check(params[spec.name])
            if problem:
                raise StrategyValidationError(
                    f"tool '{self.name}' parameter '{spec.name}': {problem}"
                )
            normalised[spec.name] = params[spec.name]
        if self.validator is not None:
            try:
                checked = self.validator(dict(normalised))
            except StrategyValidationError:
                raise
            except ValueError as exc:
                raise StrategyValidationError(f"tool '{self.name}': {exc}") from exc
            if not isinstance(checked, Mapping):
                raise StrategyValidationError(
                    f"tool '{self.name}': its validator must return a mapping of parameters"
                )
            normalised = dict(checked)
        return normalised

    def execute(self, params: Mapping[str, Any], executor: BatchExecutor | None = None) -> dict[str, Any]:
        """Run this tool (a one-element strategy) through the SOC."""
        if self.func is None:
            raise StrategyValidationError(f"tool '{self.name}' has no implementation registered")
        clean = self.check_params(params)
        return self.func(executor=executor, **clean)


class ToolManager:
    """Registry + validator + executor for the ``agent`` side of INTERFACES §6."""

    def __init__(
        self,
        tools: Iterable[Tool] = (),
        *,
        executor: BatchExecutor | None = None,
    ) -> None:
        self._tools: dict[str, Tool] = {}
        self._executor = executor if executor is not None else BatchExecutor()
        for tool in tools:
            self.register(tool)

    # -- registry ----------------------------------------------------------------------
    def register(self, tool: Tool) -> None:
        """Add a tool to the registry (duplicates are a programming error)."""
        if tool.name in self._tools:
            raise StrategyValidationError(f"tool '{tool.name}' is already registered")
        self._tools[tool.name] = tool
        logger.debug("registered tool %s", tool.name)

    def get_tool(self, name: str) -> Tool | None:
        """Return a registered tool, or ``None`` (logged) when it is unknown."""
        tool = self._tools.get(name)
        if tool is None:
            logger.warning("unknown tool requested: %s (known: %s)", name, self.get_available_tools())
        return tool

    def get_available_tools(self) -> list[str]:
        """Registry order: the tool names usable inside the target environment (``E``)."""
        return list(self._tools)

    def get_tool_descriptions(self, available: Sequence[str] | None = None) -> str:
        """The ``T_A`` section of ``P = [C, T_A, E]`` (INTERFACES §6 / §8).

        Rendered by the catalogue, not here, so one renderer owns the frozen format
        and the tool tables cannot drift apart over it.

        Args:
            available: restrict the text to these tool names — the tool set **discovered**
                in the environment (paper Eq. 3). ``None`` renders everything registered.

        Raises:
            StrategyValidationError: a registered tool is absent from the catalogue, so
                the text could not be a faithful rendering of §6.
        """
        from battlefield.soc.tool_catalogue import (  # noqa: PLC0415 - path shim is the caller's
            ToolSpecError,
            render_tool_descriptions,
            spec_for,
        )

        wanted = None if available is None else set(available)
        specs = []
        for name in self._tools:
            if wanted is not None and name not in wanted:
                continue
            try:
                specs.append(spec_for(name))
            except ToolSpecError as exc:  # pragma: no cover - catalogue/binding mismatch
                raise StrategyValidationError(str(exc)) from exc
        return render_tool_descriptions(specs)

    @property
    def executor(self) -> BatchExecutor:
        """The SOC transport used by this manager."""
        return self._executor

    def vm_config(self) -> VMConfig:
        """VM pair / attack mode the executor will use."""
        return self._executor.vm_config()

    # -- validation --------------------------------------------------------------------
    def validate_strategy(self, strategy: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Validate a full strategy against the §6 registry.

        Returns the canonical ``[{"tool": ..., "params": {...}}]`` list.

        Raises:
            StrategyValidationError: not a non-empty sequence, unknown tool, unknown or
                missing parameter, or a parameter of the wrong JSON type.
        """
        if isinstance(strategy, (str, bytes)) or not isinstance(strategy, Sequence):
            raise StrategyValidationError(
                f"strategy must be a list of tool calls, got {type(strategy).__name__}"
            )
        if not strategy:
            raise StrategyValidationError("strategy is empty; nothing to deploy")
        calls: list[dict[str, Any]] = []
        for index, call in enumerate(strategy):
            if not isinstance(call, Mapping):
                raise StrategyValidationError(
                    f"strategy entry #{index} must be an object with 'tool' and 'params'"
                )
            name = str(call.get("tool") or call.get("name") or "").strip()
            if not name:
                raise StrategyValidationError(f"strategy entry #{index} has no 'tool' name")
            tool = self._tools.get(name)
            if tool is None:
                raise StrategyValidationError(
                    f"strategy entry #{index}: unknown tool '{name}'; known tools: "
                    f"{self.get_available_tools()}"
                )
            params = call.get("params", call.get("parameters", {})) or {}
            calls.append({"tool": name, "params": tool.check_params(params)})
        return calls

    # -- execution ---------------------------------------------------------------------
    def execute_strategy(
        self,
        strategy: Sequence[Mapping[str, Any]],
        *,
        red_vm: str | None = None,
        blue_vm: str | None = None,
        attack_mode: str | None = None,
        timeout_s: float | None = None,
    ) -> dict[str, Any]:
        """Deploy the **entire** strategy in exactly one SOC request.

        Returns the SOC response enriched with the full feedback vector
        (``rs_exe`` / ``rs_attack`` / ``rs_service`` / ``F_i``) — see
        :meth:`agent.tools.batch_executor.BatchExecutor.execute_strategy`.
        """
        calls = self.validate_strategy(strategy)
        logger.info("executing a %d-tool strategy as one combined round: %s", len(calls), calls)
        return self._executor.execute_strategy(
            calls,
            red_vm=red_vm,
            blue_vm=blue_vm,
            attack_mode=attack_mode,
            timeout_s=timeout_s,
        )

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
        """Execute one registered tool (one-element strategy, still one request)."""
        calls = self.validate_strategy([{"tool": tool, "params": dict(params or {})}])
        return self._executor.execute_tool(
            calls[0]["tool"],
            calls[0]["params"],
            red_vm=red_vm,
            blue_vm=blue_vm,
            attack_mode=attack_mode,
            timeout_s=timeout_s,
        )
