# SPDX-License-Identifier: Apache-2.0
"""Security Orchestration Center (SOC) of SecLoop -- paper Section II-B-3.

The SOC is the three-component controller layer that turns an LLM-generated
security strategy into a measured three-dimensional feedback vector:

===========================  =====================================================
:class:`RedTeamController`   runs the attack sequence on the red VM and reports
                             stage-level results -> ``rs_attack`` (Eq. 11)
:class:`BlueTeamController`  deploys the whole strategy on the blue VM in one
                             pass -> ``rs_exe`` (Eq. 10)
:class:`PolicyExecutionValidator`
                             computes ``rs_exe``/``rs_attack``/``rs_service`` and
                             ``F_i`` (Eq. 13) -- a pure function
===========================  =====================================================

Supporting pieces:

* :class:`SocRoundPipeline` -- the fixed round timing of ``docs/INTERFACES.md`` §5
  (one deployment, one attack, one probe, one snapshot restore);
* :class:`VmPool` -- lock-protected VM-pair checkout;
* :class:`ServiceProbe` -- the real HTTP + TCP probe behind ``rs_service``;
* :class:`VagrantDriver` -- timeout-guarded Vagrant access;
* :class:`IaCGenerator` -- renders the 2-VM lab IaC (it never starts a VM).

Importing this package has no side effects: no logging configuration, no file
access, no VM/Vagrant import.  ``python-vagrant`` and ``flask`` are only needed
when the corresponding functionality is actually used.
"""

from .blue_team_controller import BlueTeamController
from .capability_probe import (
    CapabilityProbeError,
    TargetCapabilities,
    parse_probe_output,
    probe_capabilities,
)
from .execution_pipeline import PipelineConfig, RequestError, RoundRequest, SocRoundPipeline
from .policy_execution_validator import PolicyExecutionValidator, validate
from .red_team_controller import AttackResultError, RedTeamController, parse_attack_result
from .service_probe import ServiceProbe, ServiceProbeResult
from .tool_catalogue import (
    TOOL_CATALOGUE,
    TOOL_NAMES,
    ToolSpec,
    ToolSpecError,
    names_from_capabilities,
)
from .vagrant_driver import (
    SshResult,
    VagrantCommandTimeout,
    VagrantDriver,
    VagrantSnapshotError,
    VagrantUnavailableError,
)
from .vm_pool import VmPair, VmPool, VmPoolExhausted


def __getattr__(name: str):  # PEP 562
    """Lazy access to the IaC generator.

    ``iac_generator`` is imported on first use rather than eagerly, so
    ``python -m soc.iac_generator`` (the documented way to render the lab IaC)
    does not re-import the module as ``__main__`` and emit a runpy warning.
    ``from soc import IaCGenerator`` and ``soc.IaCGenerator`` both keep working.
    """
    if name in {"IaCGenerator", "ENV_PRESETS"}:
        from . import iac_generator

        return getattr(iac_generator, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # paper §II-B-3
    "BlueTeamController",
    "RedTeamController",
    "PolicyExecutionValidator",
    "validate",
    # orchestration
    "SocRoundPipeline",
    "PipelineConfig",
    "RoundRequest",
    "RequestError",
    "VmPool",
    "VmPair",
    "VmPoolExhausted",
    # lab plumbing
    "ServiceProbe",
    "ServiceProbeResult",
    "VagrantDriver",
    "VagrantCommandTimeout",
    "VagrantSnapshotError",
    "VagrantUnavailableError",
    "SshResult",
    "IaCGenerator",
    "ENV_PRESETS",
    # attack contract
    "parse_attack_result",
    "AttackResultError",
    "ToolSpecError",
    # the one tool table, and what a target can actually do with it (INTERFACES §6)
    "TOOL_CATALOGUE",
    "TOOL_NAMES",
    "ToolSpec",
    "names_from_capabilities",
    "TargetCapabilities",
    "CapabilityProbeError",
    "parse_probe_output",
    "probe_capabilities",
]
