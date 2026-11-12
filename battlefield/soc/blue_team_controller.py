# SPDX-License-Identifier: Apache-2.0
"""Blue Team Controller (BTC) for SecLoop -- paper Section II-B-3, Eq. (8).

    E_BVM = BTC(S_k)

The BTC turns one **whole** strategy -- the list of tool calls produced by the
LLM agent for this round -- into commands, executes them on the blue-team VM in
a single deployment pass, and reports one result per tool call.  That list is
the numerator/denominator of ``rs_exe`` (Eq. 10).

Why one round, not N
--------------------------------
One HTTP round trip per tool would mean a full red-team attack plus a snapshot restore
for every tool, so a *composite* strategy would never be evaluated as one defence.  Here
``deploy_strategy`` simply loops over
the strategy; the SOC server then launches **one** attack against the fully
deployed strategy and takes ``rs_exe`` and ``rs_attack`` from that same round
(``docs/INTERFACES.md`` §5, paper Eq. 8).

Tool registry (``docs/INTERFACES.md`` §6)
----------------------------------------
The catalogue lives in :mod:`soc.tool_catalogue` — **one** table for the whole
repository, shared with the agent and the training reward.  This module keeps no
copy of its own: two tables encoding the same tools under similar names is how the
Linux lab ends up offering a Windows-only tool to the model while ``bash -lc`` makes
that call *appear* to succeed (see that module's docstring).

Every command is wrapped in ``timeout`` + ``bash -lc`` on the guest, so a hung
tool cannot wedge a SOC worker, and the real remote exit status decides
``success`` (no "stdout was non-empty, therefore it worked" guessing).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Mapping
from typing import Any

from .capability_probe import (
    DEFAULT_PROBE_TIMEOUT_S,
    CapabilityProbeError,
    TargetCapabilities,
    probe_capabilities,
)
from .policy_execution_validator import MAX_OUTPUT_CHARS
from .tool_catalogue import (
    DEFAULT_TOOL_TIMEOUT_S,
    ToolSpecError,
    build_command as render_tool_command,
)
from .vagrant_driver import VagrantDriver

logger = logging.getLogger(__name__)

#: Re-exported so ``soc.ToolSpecError`` and ``from .blue_team_controller import
#: ToolSpecError`` keep working; the catalogue owns the exception.
__all__ = ["BlueTeamController", "CapabilityProbeError", "ToolSpecError"]

TOOL_TIMEOUT_ENV = "SOC_TOOL_TIMEOUT_S"


class BlueTeamController:
    """Deploys defensive strategies on the blue-team VM via Vagrant SSH.

    Args:
        driver: optional :class:`~soc.vagrant_driver.VagrantDriver` (dependency
            injection: tests pass a fake, production passes nothing).
        vagrant_root: Vagrant root directory; defaults to ``SOAR_VAGRANT_ROOT``
            or ``<repo>/SecLoop/vagrant``.
        default_blue_vm: VM name used when the caller does not pass one.
        tool_timeout_s: guest-side budget per tool (``SOC_TOOL_TIMEOUT_S``).
        capabilities: pre-probed target capabilities (dependency injection / caching by
            the caller). When omitted they are discovered lazily on first use.
        probe_timeout_s: budget for the capability probe itself.
    """

    def __init__(
        self,
        driver: VagrantDriver | None = None,
        *,
        vagrant_root: str | os.PathLike[str] | None = None,
        default_blue_vm: str = "target",
        tool_timeout_s: float | None = None,
        capabilities: TargetCapabilities | None = None,
        probe_timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
    ) -> None:
        self.driver = driver or VagrantDriver(root=vagrant_root)
        self.default_blue_vm = default_blue_vm
        self.tool_timeout_s = float(
            tool_timeout_s
            if tool_timeout_s is not None
            else os.getenv(TOOL_TIMEOUT_ENV, DEFAULT_TOOL_TIMEOUT_S)
        )
        self.probe_timeout_s = float(probe_timeout_s)
        self._capabilities: dict[str, TargetCapabilities] = {}
        if capabilities is not None:
            self._capabilities[capabilities.vm] = capabilities

    # --------------------------------------------------------- capabilities

    def capabilities(self, vm: str | None = None, *, refresh: bool = False) -> TargetCapabilities:
        """What **this** blue-team VM can do, discovered from the VM itself.

        ``T_A`` is "the tools available in the current environment" (paper Eq. 3), so the
        available set comes from a probe — not from a configuration value and not from a
        per-OS table in the catalogue, neither of which can know whether this particular
        machine has ``iptables`` or working ``sudo``.

        The result is cached **per VM**: a ``SOAR_VM_POOL`` with several pairs means one
        deployment target per round, and a single cache slot would answer for the wrong
        host. Callers therefore pass the VM a round will actually deploy to.

        Raises:
            CapabilityProbeError: the VM could not be probed; ``T_A`` would be a guess.
        """
        target = vm or self.default_blue_vm
        if not refresh and target in self._capabilities:
            return self._capabilities[target]
        probed = probe_capabilities(self.driver, target, timeout_s=self.probe_timeout_s)
        self._capabilities[target] = probed
        logger.info(
            "BTC: capabilities of %s -> %s (%s), tools=%s",
            target,
            probed.os_name,
            probed.renderer,
            list(probed.available_tools),
        )
        return probed

    @property
    def supported_tools(self) -> list[str]:
        """Tool names this controller discovered it can execute (§6).

        Derived from the probe, so it reflects *this* VM. A static list filtered by a
        configured platform string would offer a Windows-only tool on a Linux target and
        then "execute" it through ``bash -lc``, inflating ``rs_exe`` for a deployment
        that never happened.
        """
        return sorted(self.capabilities().available_tools)

    def build_command(
        self, tool: str, params: Mapping[str, Any] | None = None, *, vm: str | None = None
    ) -> str:
        """Render the guest-side shell command for one tool call.

        The rendering itself lives in :func:`soc.tool_catalogue.build_command`, and the
        discovered capability set is enforced here, so the catalogue and the SOC cannot
        disagree about what a tool runs or whether it may run at all.

        Args:
            tool: tool name, e.g. ``block_ip``.
            params: the tool parameters.
            vm: the VM the command will run on. Defaults to ``default_blue_vm``; pass the
                round's actual blue VM, or a pooled round could be checked against one
                host and executed on another.

        Returns:
            A single shell command, wrapped in ``timeout`` + ``bash -lc``.

        Raises:
            ToolSpecError: unknown tool, not available on that target, or missing or
                invalid parameter.
        """
        caps = self.capabilities(vm)
        return render_tool_command(
            tool,
            params,
            available=caps.available_tools,
            renderer=caps.renderer,
            tool_timeout_s=self.tool_timeout_s,
        )

    # ------------------------------------------------------------- deployment

    def deploy_strategy(
        self,
        tools: list[dict[str, Any]] | list[str],
        blue_vm: str | None = None,
        timeout_s: float | None = None,
    ) -> list[dict[str, Any]]:
        """Execute the **whole** strategy in one pass and report per tool.

        Args:
            tools: the strategy -- a list of ``{"tool": ..., "params": {...}}``
                calls (a bare string is accepted as a legacy ``bash`` command).
            blue_vm: blue-team VM name; defaults to ``default_blue_vm``.
            timeout_s: guest-side budget per tool; defaults to ``tool_timeout_s``.

        Returns:
            Exactly one ``{tool, success, output, error}`` entry per input entry,
            in strategy order.  The length always equals ``len(tools)`` so Eq. 10
            can never lose or invent a tool call, and an unsupported or malformed
            call becomes an explicit failure entry rather than a silent skip.

        Raises:
            ValueError: ``tools`` is not a list.
        """
        if not isinstance(tools, list):
            raise ValueError(f"strategy must be a list of tool calls, got {type(tools).__name__}")

        vm = blue_vm or self.default_blue_vm
        budget = float(timeout_s if timeout_s is not None else self.tool_timeout_s)
        results: list[dict[str, Any]] = []
        logger.info(
            "BTC: deploying a %d-tool strategy on %s in one pass (rs_exe source)",
            len(tools),
            vm,
        )

        for index, call in enumerate(tools):
            tool_name, params, spec_error = self._unpack_call(index, call)
            if spec_error is not None:
                logger.error("BTC: tool %d/%d rejected: %s", index + 1, len(tools), spec_error)
                results.append(
                    {"tool": tool_name, "success": False, "output": "", "error": spec_error}
                )
                continue

            try:
                command = self.build_command(tool_name, params, vm=vm)
            except ToolSpecError as exc:
                logger.error("BTC: tool %d/%d rejected: %s", index + 1, len(tools), exc)
                results.append(
                    {"tool": tool_name, "success": False, "output": "", "error": str(exc)}
                )
                continue

            logger.info("BTC: tool %d/%d on %s: %s", index + 1, len(tools), vm, command)
            started = time.monotonic()
            ssh = self.driver.ssh(vm, command, timeout_s=budget)
            elapsed = time.monotonic() - started

            if ssh.timed_out:
                error = f"tool timed out after {budget:.0f}s (host watchdog)"
            elif ssh.returncode == 124:
                error = f"tool hit the guest-side timeout of {budget:.0f}s"
            elif ssh.returncode != 0:
                error = ssh.error or f"exit status {ssh.returncode}"
            else:
                error = None

            success = error is None
            output = self._trim(ssh.stdout or "")
            if success:
                logger.info("BTC: tool %d/%d (%s) succeeded in %.1fs", index + 1, len(tools), tool_name, elapsed)
            else:
                logger.warning(
                    "BTC: tool %d/%d (%s) failed after %.1fs: %s", index + 1, len(tools), tool_name, elapsed, error
                )
            results.append(
                {"tool": tool_name, "success": success, "output": output, "error": error}
            )

        deployed = sum(1 for result in results if result["success"])
        logger.info("BTC: strategy deployment finished: %d/%d tools succeeded", deployed, len(results))
        return results

    # ------------------------------------------------------------- snapshots

    def snapshot_name(self, vm: str) -> str:
        """Initial-snapshot name for ``vm`` (``docs/INTERFACES.md`` §1)."""
        return f"{vm}_init"

    def restore_snapshot(self, vm: str | None = None) -> None:
        """Restore ``vm`` to its ``<vm>_init`` snapshot.

        The SOC calls this at the end of every round so the next round starts
        from a clean VM.  It is called for the blue VM; the red VM is only an
        attacker and keeps no state that the lab cares about.

        Raises:
            VagrantSnapshotError: the snapshot is missing or the restore failed.
                A silent no-op here would let the *next* round measure a dirty
                VM, so the failure is deliberately not swallowed -- the SOC
                server turns it into a failed request.
        """
        target_vm = vm or self.default_blue_vm
        name = self.snapshot_name(target_vm)
        logger.info("BTC: restoring snapshot %s on %s", name, target_vm)
        self.driver.snapshot_restore(target_vm, name)

    # --------------------------------------------------------------- helpers

    @staticmethod
    def _unpack_call(index: int, call: Any) -> tuple[str, Mapping[str, Any], str | None]:
        """Split one strategy entry into ``(tool_name, params, error)``."""
        if isinstance(call, str):
            logger.warning(
                "BTC: strategy entry %d is a bare string; treating it as a legacy bash command",
                index,
            )
            return "bash", {"command": call}, None
        if not isinstance(call, Mapping):
            return (
                "",
                {},
                f"strategy entry {index} must be an object like "
                f'{{"tool": ..., "params": {{...}}}}, got {type(call).__name__}',
            )
        tool_name = call.get("tool", call.get("tool_name", ""))
        if not isinstance(tool_name, str) or not tool_name.strip():
            return "", {}, f"strategy entry {index} has no usable 'tool' name"
        params = call.get("params")
        if params is None:
            params = {}
        return tool_name.strip(), params, None

    @staticmethod
    def _trim(output: str) -> str:
        if len(output) <= MAX_OUTPUT_CHARS:
            return output
        return output[:MAX_OUTPUT_CHARS] + "... [truncated]"
