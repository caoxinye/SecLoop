# SPDX-License-Identifier: Apache-2.0
"""One tool table, and the requirements it declares (paper Eq. 3).

Three drifting tool lists are the failure mode of ``docs/INTERFACES.md`` §6: the prompt
can say ``Platform: Linux`` while ``agent/config.json`` offers ``powershell``; the model
then emits it, the SOC renders ``{command}`` through ``bash -lc``, and a deployment that
never happened scores as a successful defence in ``rs_exe``.

There are two separate questions, and this file pins both:

* **What is a tool?** — the catalogue (`battlefield/soc/tool_catalogue.py`), tested here.
* **What is available?** — a *measurement* of the target, tested in
  ``test_capability_probe.py``. The catalogue must not answer it: it declares the
  requirements to look for, never a per-OS list.

Standard library only, and pytest-free so ``python tests/lab/test_tool_catalogue.py``
works too. The agent-side tests need ``requests`` and skip themselves without it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _labkit  # noqa: E402  (path bootstrap must come first)
from _labkit import REPO_ROOT, run_module_tests  # noqa: E402

sys.path.insert(0, str(REPO_ROOT))

from battlefield.soc.tool_catalogue import (  # noqa: E402
    CATALOGUE_BY_NAME,
    RENDERERS,
    SOC_RENDERERS,
    TOOL_CATALOGUE,
    TOOL_NAMES,
    ToolSpecError,
    build_command,
    catalogue_members,
    detection_targets,
    documented_command,
    names_from_capabilities,
    renderer_for_os,
    spec_for,
)

SOC_BTC_PATH = REPO_ROOT / "battlefield" / "soc" / "blue_team_controller.py"
AGENT_REGISTRY_PATH = REPO_ROOT / "agent" / "tools" / "security_tools.py"
AGENT_CONFIG_PATH = REPO_ROOT / "agent" / "config.json"

# NOTE: the agent-side behaviour (importing `agent.tools`, `create_security_tools`,
# `get_tool_descriptions`) is deliberately **not** tested here. This file stays
# stdlib-only so it runs on any machine; those tests need `requests` and live in
# `tests/test_agent_tool_binding.py`. A guarded import that swallows ImportError and
# then `return`-s *passes*, so a completely broken agent package would report green
# here. Never do that.


# ---------------------------------------------------------------------------------------
# One table
# ---------------------------------------------------------------------------------------
def test_the_catalogue_holds_the_papers_three_tools_in_contract_order() -> None:
    assert TOOL_NAMES == ("block_ip", "bash", "powershell")
    assert set(CATALOGUE_BY_NAME) == set(TOOL_NAMES)
    assert len(CATALOGUE_BY_NAME) == len(TOOL_CATALOGUE), "duplicate name in the catalogue"


def test_entries_declare_requirements_rather_than_an_operating_system() -> None:
    """A table cannot know what a machine has; it may only say what to look for."""
    for spec in TOOL_CATALOGUE:
        assert spec.renderer in RENDERERS, spec.renderer
        assert spec.template, f"{spec.name} has no template"
        assert not hasattr(spec, "platforms"), (
            f"{spec.name} carries a hard-coded per-OS list; T_A must be probed"
        )
    # Every entry must be detectable, or its availability would be unfalsifiable.
    for spec in TOOL_CATALOGUE:
        assert spec.requires_any or spec.renderer not in SOC_RENDERERS, (
            f"{spec.name} declares nothing to detect, so its availability is unfalsifiable"
        )


def test_the_requirements_match_the_documented_commands() -> None:
    assert spec_for("block_ip").requires_any == ("iptables",)
    assert spec_for("block_ip").requires_root is True, "iptables needs CAP_NET_ADMIN"
    assert spec_for("block_ip").privileged is True
    assert "bash" in spec_for("bash").requires_any
    assert spec_for("bash").requires_root is False
    assert spec_for("powershell").renderer == "powershell"


def test_the_documented_command_is_derived_not_restated() -> None:
    """``{ip}`` -> ``<ip>``; a second stored copy is how the tables drifted."""
    assert spec_for("block_ip").documented_command() == "iptables -I INPUT -s <ip> -j DROP"
    assert spec_for("bash").documented_command() == "<command>"
    assert documented_command("{ip} and {command}") == "<ip> and <command>"


def test_the_detection_targets_come_from_the_catalogue() -> None:
    expected = sorted({name for spec in TOOL_CATALOGUE for name in spec.requires_any})
    assert list(detection_targets()) == expected
    assert "iptables" in detection_targets()


def test_the_operating_system_maps_to_an_interpreter_family() -> None:
    assert renderer_for_os("Linux") == "posix"
    assert renderer_for_os("Darwin") == "posix"
    assert renderer_for_os("Windows") == "powershell"
    # These are POSIX shells on Windows: the probe printing its markers proves a POSIX
    # shell ran it, so an OS-name inference must not override that observation.
    assert renderer_for_os("MINGW64_NT-10.0") == "posix"
    assert renderer_for_os("CYGWIN_NT-10.0") == "posix"
    assert renderer_for_os("") == "posix", "an unknown answer must not invent a Windows box"
    assert renderer_for_os("unknown") == "posix"


def test_a_posix_shell_on_windows_still_counts_as_posix() -> None:
    """Guard: the probe ran, so a POSIX shell demonstrably exists there."""
    assert names_from_capabilities(
        renderer=renderer_for_os("MINGW64_NT-10.0"),
        binaries={"bash", "sh"},
        root_available=False,
    ) == ("bash",)


def test_the_soc_keeps_no_second_table() -> None:
    source = SOC_BTC_PATH.read_text(encoding="utf-8")
    assert "_TOOL_SPECS" not in source, (
        "blue_team_controller.py holds a private tool table; there is exactly one "
        "(battlefield/soc/tool_catalogue.py)"
    )


def test_the_agent_registry_is_derived_from_the_catalogue() -> None:
    source = AGENT_REGISTRY_PATH.read_text(encoding="utf-8")
    assert "from battlefield.soc.tool_catalogue import" in source
    assert '"iptables -I INPUT -s {ip} -j DROP"' not in source, "the template is restated"


def test_the_agent_config_does_not_declare_its_own_tool_list() -> None:
    """``environment.tools`` is what creates the Linux/``powershell`` contradiction."""
    document = json.loads(AGENT_CONFIG_PATH.read_text(encoding="utf-8"))
    assert "tools" not in document.get("environment", {}), (
        "agent/config.json declares its own tool list; the available set must be "
        "probed from the target"
    )


# ---------------------------------------------------------------------------------------
# Availability is a function of the probe, not of the table
# ---------------------------------------------------------------------------------------
def test_the_same_catalogue_answers_differently_per_probed_environment() -> None:
    linux = names_from_capabilities(
        renderer="posix", binaries={"bash", "iptables"}, root_available=True
    )
    no_root = names_from_capabilities(
        renderer="posix", binaries={"bash", "iptables"}, root_available=False
    )
    bare = names_from_capabilities(renderer="posix", binaries=set(), root_available=True)
    windows = names_from_capabilities(
        renderer="powershell", binaries={"powershell"}, root_available=True
    )
    assert linux == ("block_ip", "bash")
    assert no_root == ("bash",)
    assert bare == ()
    assert windows == (), "this SOC drives posix only, so a Windows guest yields nothing"


def test_a_windows_only_tool_is_never_offered_in_this_repository() -> None:
    for renderer in ("posix", "powershell"):
        assert "powershell" not in names_from_capabilities(
            renderer=renderer,
            binaries={"bash", "iptables", "pwsh", "powershell"},
            root_available=True,
        )


# ---------------------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------------------
def test_block_ip_is_privileged_and_bash_is_not() -> None:
    privileged = build_command("block_ip", {"ip": "192.168.57.199"})
    plain = build_command("bash", {"command": "true"})
    assert "sudo -n iptables -I INPUT -s 192.168.57.199 -j DROP" in privileged
    assert "sudo" not in plain
    for command in (privileged, plain):
        assert command.startswith("timeout --signal=TERM --kill-after=5 60 bash -lc ")


def test_a_tool_outside_the_discovered_set_is_refused() -> None:
    """Rendering an unavailable tool as ``{command}`` and letting it succeed inflates
    rs_exe."""
    try:
        build_command("block_ip", {"ip": "192.168.57.199"}, available=["bash"])
    except ToolSpecError as exc:
        assert "not available on this target" in str(exc)
    else:
        raise AssertionError("a tool the target cannot run must be refused, not rendered")


def test_a_powershell_tool_is_refused_by_a_posix_runner() -> None:
    try:
        build_command("powershell", {"command": "Get-Process"})
    except ToolSpecError as exc:
        assert "needs a powershell session" in str(exc)
    else:
        raise AssertionError("powershell under a posix runner must be refused")


def test_an_unknown_tool_is_refused() -> None:
    try:
        build_command("nope")
    except ToolSpecError:
        pass
    else:
        raise AssertionError("an unknown tool must raise")


def test_parameter_validation_matches_the_soc_contract() -> None:
    cases = (
        ("block_ip", {}),                    # missing required
        ("block_ip", {"ip": "   "}),         # blank
        ("block_ip", {"ip": "not-an-ip"}),   # not an address
        ("block_ip", {"ip": "::1"}),         # IPv6
        ("bash", {}),                        # missing required
        ("bash", {"command": "ok\x00null"}),  # NUL byte
        ("bash", {"command": 5}),            # not a string
        ("bash", "not-a-mapping"),           # params not an object
    )
    for name, params in cases:
        try:
            build_command(name, params)  # type: ignore[arg-type]
        except ToolSpecError:
            pass
        else:
            raise AssertionError(f"build_command({name!r}, {params!r}) must raise ToolSpecError")


def test_the_legacy_ip_address_alias_still_renders() -> None:
    """Kept intentionally: the contract says `ip`, old strategies say `ip_address`."""
    assert "192.168.57.199" in build_command("block_ip", {"ip_address": "192.168.57.199"})


def test_declared_names_are_checked_for_membership_only() -> None:
    """Availability belongs to the probe; this only rejects names that do not exist."""
    assert catalogue_members(["block_ip", "bash"]) == ("block_ip", "bash")
    try:
        catalogue_members(["block_ip", "nope"])
    except ToolSpecError:
        pass
    else:
        raise AssertionError("an unknown name must raise")


if __name__ == "__main__":
    raise SystemExit(run_module_tests(dict(globals())))
