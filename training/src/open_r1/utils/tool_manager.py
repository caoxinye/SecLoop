# SPDX-License-Identifier: Apache-2.0
"""Re-export of the authoritative ``Tool`` / ``ToolManager`` (``INTERFACES.md`` §6).

``ToolManager`` is *defined* in ``agent/tools/tool_manager.py`` and re-exported by
``agent/tools/security_tools.py``.  Code that only needs the container classes can
import them here; nothing is duplicated.
"""

from __future__ import annotations

from open_r1._syspath import ensure_repo_root_on_path

ensure_repo_root_on_path()

from agent.tools.tool_manager import (  # noqa: E402  (import after sys.path shim)
    StrategyValidationError,
    Tool,
    ToolManager,
)
from battlefield.soc.tool_catalogue import render_tool_descriptions  # noqa: E402

__all__ = [
    "StrategyValidationError",
    "Tool",
    "ToolManager",
    "render_tool_descriptions",
]
