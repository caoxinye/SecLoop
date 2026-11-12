# SPDX-License-Identifier: Apache-2.0
"""Training-side view of the authoritative security tool catalogue.

``INTERFACES.md`` §6: the single source of truth for the response tools is
``battlefield/soc/tool_catalogue.py``.  ``agent/tools/security_tools.py`` binds the
client implementations to that catalogue; this module re-exports the agent's view of it
and **contains no tool implementation**, so the reward cascade validates the model's tool
calls against exactly the catalogue the inference agent advertises.  Maintaining a
second copy here is what §6 forbids.

Note the two different sets: :data:`TOOL_NAMES` is the full catalogue, while a
``ToolManager`` from ``create_security_tools`` registers only the tools the *current
environment* can run.  Membership checks belong on the catalogue; availability belongs to
the manager.
"""

from __future__ import annotations

from open_r1._syspath import ensure_repo_root_on_path

ensure_repo_root_on_path()

from agent.tools.security_tools import (  # noqa: E402  (import after sys.path shim)
    TOOL_NAMES,
    TOOL_SPECS,
    ParameterSpec,
    Tool,
    ToolManager,
    bash,
    block_ip,
    create_security_tools,
    get_tool_descriptions,
    powershell,
)

__all__ = [
    "TOOL_NAMES",
    "TOOL_SPECS",
    "ParameterSpec",
    "Tool",
    "ToolManager",
    "bash",
    "block_ip",
    "create_security_tools",
    "get_tool_descriptions",
    "powershell",
]
