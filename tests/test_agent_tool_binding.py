# SPDX-License-Identifier: Apache-2.0
"""The agent side of the shared tool table: the package must actually import.

Two failure modes are invisible to a guarded import, so both are covered here:

1. ``import agent.tools`` can raise ``ImportError`` while the suite still reports
   success: a test that wraps the import in ``try: ... except ImportError`` and then
   ``return``-s **passes**. The agent CLI and the training entry point would both be
   dead while the suite is green.
2. A name can stay in a module's ``__all__`` and in a function body after it is removed
   from the module, so the failure waits until the function is called.

So: a plain import with no guard, plus the behaviour it would hide. This file needs
``requests`` (the SOC client); that is why it is not in ``tests/lab/``, which stays
stdlib-only on purpose.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

pytest.importorskip("requests", reason="the SOC client needs requests")

from battlefield.soc.tool_catalogue import TOOL_NAMES  # noqa: E402


# ---------------------------------------------------------------------------------------
# The import itself
# ---------------------------------------------------------------------------------------
def test_the_agent_package_imports() -> None:
    """No `try`, no `except`, no `return`: a broken package must fail this file."""
    import agent.tools  # noqa: F401


def test_every_public_name_the_package_advertises_exists() -> None:
    """An ``__all__`` entry the module does not define is a latent ``NameError``."""
    import agent.tools as tools

    missing = [name for name in tools.__all__ if not hasattr(tools, name)]
    assert missing == [], f"agent.tools advertises names it does not provide: {missing}"


def test_the_advertised_callables_are_callable() -> None:
    import agent.tools as tools

    for name in ("create_security_tools", "get_tool_descriptions", "render_tool_descriptions"):
        assert callable(getattr(tools, name)), name


def test_the_agent_cli_starts_and_prints_a_prompt() -> None:
    """The command every document tells the reader to run.

    Uses a declared tool set so it stays offline (the probed path needs a running SOC).
    """
    fixture = REPO_ROOT / "tests" / "lab" / "fixtures" / "fastlog_parser_fixture.txt"
    result = subprocess.run(
        [
            sys.executable,
            "-B",  # the child does not inherit sys.dont_write_bytecode (quickstart §7)
            str(REPO_ROOT / "agent" / "main.py"),
            "--print-prompt",
            "--tools",
            "block_ip,bash",
            "--ids-summary-file",
            str(fixture),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, f"agent/main.py failed:\n{result.stdout}\n{result.stderr}"
    assert "- Available tools: block_ip, bash" in result.stdout
    assert "powershell" not in result.stdout


# ---------------------------------------------------------------------------------------
# The behaviour a guarded import would hide
# ---------------------------------------------------------------------------------------
def test_the_agent_and_the_catalogue_agree_on_membership() -> None:
    from agent.tools.security_tools import TOOL_NAMES as AGENT_TOOL_NAMES

    assert tuple(AGENT_TOOL_NAMES) == TOOL_NAMES


def test_the_agent_registers_exactly_what_the_probe_found() -> None:
    from agent.tools.security_tools import create_security_tools

    manager = create_security_tools(available=["block_ip", "bash"])
    assert sorted(manager.get_available_tools()) == ["bash", "block_ip"]
    assert manager.get_tool("powershell") is None, (
        "a tool the environment cannot run must be unusable, not merely undocumented"
    )


def test_the_agent_without_a_probe_registers_the_full_catalogue_for_membership() -> None:
    """The training/reward path needs name membership; a manager without a probe is not one."""
    from agent.tools.security_tools import create_security_tools

    manager = create_security_tools()
    assert sorted(manager.get_available_tools()) == sorted(TOOL_NAMES)


def test_the_single_renderer_is_the_catalogue_one() -> None:
    """There must be one implementation of the frozen §6 line format, not two."""
    import agent.tools as tools

    assert tools.render_tool_descriptions is not None
    rendered = tools.get_tool_descriptions(["block_ip", "bash"])
    assert rendered.splitlines()[0].startswith("- block_ip: ")
    assert "powershell" not in rendered


def test_the_ta_prompt_text_follows_the_probe() -> None:
    from agent.tools.security_tools import get_tool_descriptions

    probed = get_tool_descriptions(["block_ip", "bash"])
    assert "block_ip" in probed and "bash" in probed
    assert "powershell" not in probed, "the exact failure mode"
    # The same call with only `bash` reflects that machine, not a platform label.
    assert "block_ip" not in get_tool_descriptions(["bash"])
