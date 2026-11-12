# SPDX-License-Identifier: Apache-2.0
"""The training prompt's ``T_A`` must come from the row's environment (paper Eq. 3).

The failure mode this file pins: rendering ``T_A`` from the full catalogue advertises
``powershell`` next to ``Platform: Linux`` on a Linux lab, while the SOC can never run
it.  The corpus records the environment each row came from, so the prompt must read it
from there.

Deliberately free of ``torch``/``trl``/``datasets``: the helpers under test are importable
on any machine, so this file is never skipped.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
_TRAINING_SRC = REPO_ROOT / "training" / "src"
for path in (str(_TRAINING_SRC), str(REPO_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from open_r1.utils.prompt_rows import (  # noqa: E402
    REQUIRED_COLUMNS,
    RowSchemaError,
    resolve_row_environment,
    resolve_row_tools,
    validate_corpus_schema,
)

LINUX_ROW = {
    "alerts": "alert line",
    "platform": "Linux",
    "description": "Ubuntu 18.04 blue-team target",
    "tools": ["block_ip", "bash"],
}
WINDOWS_ROW = {
    "alerts": "alert line",
    "platform": "Windows",
    "description": "Windows blue-team target",
    "tools": ["powershell"],
}


class FakeSplit:
    def __init__(self, columns):
        self.column_names = list(columns)


def test_a_row_declares_its_own_environment() -> None:
    assert resolve_row_tools(LINUX_ROW) == ["block_ip", "bash"]
    assert resolve_row_tools(WINDOWS_ROW) == ["powershell"]
    assert resolve_row_environment(LINUX_ROW) == (["block_ip", "bash"], "Linux")


def test_a_single_string_is_tolerated() -> None:
    """Some corpora serialise a one-tool environment as a bare string."""
    assert resolve_row_tools({**LINUX_ROW, "tools": "bash"}) == ["bash"]


def test_a_row_without_tools_is_refused_rather_than_defaulted() -> None:
    """The whole point: no silent fallback to the full catalogue."""
    with pytest.raises(RowSchemaError, match="must not fall back"):
        resolve_row_tools({**LINUX_ROW, "tools": []})
    with pytest.raises(RowSchemaError):
        resolve_row_tools({"alerts": "x", "platform": "Linux"})


def test_a_row_cannot_invent_a_tool() -> None:
    with pytest.raises(RowSchemaError):
        resolve_row_tools({**LINUX_ROW, "tools": ["block_ip", "rm -rf"]})


def test_a_row_without_a_platform_is_refused_rather_than_defaulted() -> None:
    """`E`'s Platform has no default: defaulting it would be a guess about the environment."""
    with pytest.raises(RowSchemaError, match="platform"):
        resolve_row_environment({**LINUX_ROW, "platform": ""})


def test_a_corpus_missing_an_environment_column_refuses_to_start() -> None:
    validate_corpus_schema({"train": FakeSplit(REQUIRED_COLUMNS)})
    for missing in REQUIRED_COLUMNS:
        columns = [name for name in REQUIRED_COLUMNS if name != missing]
        with pytest.raises(RowSchemaError, match=missing):
            validate_corpus_schema({"train": FakeSplit(columns)})


def test_the_training_ta_advertises_only_runnable_tools() -> None:
    """Linux must not be offered powershell on the training path."""
    from agent.tools.security_tools import create_security_tools

    tools, platform = resolve_row_environment(LINUX_ROW)
    assert platform == "Linux"
    # The trainer builds one membership manager and asks it to render the row's set.
    manager = create_security_tools()
    rendered = manager.get_tool_descriptions(tools)
    assert "block_ip" in rendered and "bash" in rendered
    assert "powershell" not in rendered, (
        "the training prompt advertised a Windows-only tool on a Linux target -- that is "
        "a tool the platform does not have, on the path the paper actually trains"
    )
    # A Windows row that really has PowerShell still renders it (the guard is not a ban).
    assert "powershell" in manager.get_tool_descriptions(resolve_row_tools(WINDOWS_ROW))
