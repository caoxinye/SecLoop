# SPDX-License-Identifier: Apache-2.0
"""Tool layer of the SecLoop agent (INTERFACES §6).

* :mod:`agent.tools.security_tools` — the 3-tool catalogue, **cross-subsystem single source
  of truth** (re-exported by ``training/src/open_r1/utils/security_tools.py``).
* :mod:`agent.tools.tool_manager` — registry, ``T_A`` rendering and strategy validation.
* :mod:`agent.tools.batch_executor` — the one-request-per-strategy SOC transport.
"""

from .batch_executor import (
    BatchExecutor,
    DatasetConfigError,
    DatasetPathError,
    SOCError,
    SOCUnavailableError,
    VMConfig,
    read_vm_config,
    soc_endpoint,
)
from .security_tools import (
    TOOL_NAMES,
    TOOL_SPECS,
    bash,
    block_ip,
    create_security_tools,
    get_tool_descriptions,
    powershell,
    render_tool_descriptions,
)
from .tool_manager import ParameterSpec, StrategyValidationError, Tool, ToolManager

__all__ = [
    "TOOL_NAMES",
    "TOOL_SPECS",
    "BatchExecutor",
    "DatasetConfigError",
    "DatasetPathError",
    "ParameterSpec",
    "SOCError",
    "SOCUnavailableError",
    "StrategyValidationError",
    "Tool",
    "ToolManager",
    "VMConfig",
    "bash",
    "block_ip",
    "create_security_tools",
    "get_tool_descriptions",
    "powershell",
    "read_vm_config",
    "render_tool_descriptions",
    "soc_endpoint",
]
