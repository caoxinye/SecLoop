# SPDX-License-Identifier: Apache-2.0
"""Capability discovery: ``T_A`` is *measured*, not assumed (paper Eq. 3).

The catalogue says what a tool **is**. This module's tests cover the part that decides
what is **available**: one probe per target, parsed into facts, from which the tool set is
derived. Every case below is an environment that yields a *different* tool set, which is
the property a per-OS table cannot have.

No VM, no driver, no network: the SSH call is a fake and the parsing is a pure function.

Standard library only, and pytest-free so ``python tests/lab/test_capability_probe.py``
works too.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _labkit  # noqa: E402  (path bootstrap must come first)
from _labkit import REPO_ROOT, run_module_tests  # noqa: E402

sys.path.insert(0, str(REPO_ROOT))

from battlefield.soc.blue_team_controller import BlueTeamController, ToolSpecError  # noqa: E402
from battlefield.soc.capability_probe import (  # noqa: E402
    CapabilityProbeError,
    capabilities_from_output,
    parse_probe_output,
    probe_capabilities,
)
from battlefield.soc.tool_catalogue import (  # noqa: E402
    BINARY_MARKER,
    OS_MARKER,
    ROOT_MARKER,
    detection_script,
    detection_targets,
)


def probe_output(os_name: str, root: bool, binaries: tuple[str, ...]) -> str:
    lines = [f"{OS_MARKER} {os_name}", f"{ROOT_MARKER} {'1' if root else '0'}"]
    lines += [f"{BINARY_MARKER} {name}" for name in binaries]
    return "\r\n".join(lines) + "\r\n"


class FakeDriver:
    """Minimal ``VagrantDriver`` stand-in that records what it was asked to run."""

    def __init__(self, stdout: str = "", returncode: int = 0, error: str | None = None) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.error = error
        self.calls: list[tuple[str, str, float | None]] = []
        self.script = ""

    def ssh(self, vm: str, command: str, timeout_s: float | None = None, watchdog_s=None):
        self.calls.append((vm, command, timeout_s))
        self.script = command
        return SimpleNamespace(
            stdout=self.stdout, returncode=self.returncode, error=self.error, timed_out=False
        )


# ---------------------------------------------------------------------------------------
# Parsing (pure)
# ---------------------------------------------------------------------------------------
def test_parsing_reads_every_marker_and_ignores_noise() -> None:
    noisy = (
        "Welcome to Ubuntu 18.04.6 LTS\r\n"
        f"{OS_MARKER} Linux\r\n"
        "Last login: whatever\r\n"
        f"{ROOT_MARKER} 1\r\n"
        f"{BINARY_MARKER} bash\r\n"
        "\r\n"
        f"{BINARY_MARKER} iptables\r\n"
        "trailing junk\r\n"
    )
    parsed = parse_probe_output(noisy)
    assert parsed.os_name == "Linux"
    assert parsed.root_available is True
    assert parsed.binaries == frozenset({"bash", "iptables"})
    assert parsed.reported_os is True
    assert parsed.renderer == "posix"


def test_parsing_marks_a_missing_os_marker() -> None:
    parsed = parse_probe_output("bash: command not found\n")
    assert parsed.reported_os is False
    assert parsed.binaries == frozenset()


def test_the_probe_script_is_derived_from_the_catalogue() -> None:
    """A hand-maintained binary list is the drift this catalogue design removes."""
    script = detection_script()
    for binary in detection_targets():
        assert f"command -v {binary}" in script, binary
    assert OS_MARKER in script and ROOT_MARKER in script
    assert script.rstrip().endswith("exit 0"), "a missing binary is information, not an error"
    assert "sudo -n true" in script, "root access must be observed, not assumed"


# ---------------------------------------------------------------------------------------
# Availability per environment
# ---------------------------------------------------------------------------------------
def available_for(os_name: str, root: bool, binaries: tuple[str, ...]) -> tuple[str, ...]:
    return capabilities_from_output(probe_output(os_name, root, binaries), vm="target").available_tools


def test_each_environment_yields_its_own_tool_set() -> None:
    """The four Linux cases differ only in what the probe *found*."""
    assert available_for("Linux", True, ("bash", "iptables")) == ("block_ip", "bash")
    assert available_for("Linux", True, ("bash",)) == ("bash",), "no iptables -> no block_ip"
    assert available_for("Linux", False, ("bash", "iptables")) == ("bash",), "no root -> no iptables rule"
    assert available_for("Linux", True, ()) == (), "nothing installed -> nothing offered"
    assert available_for("Linux", True, ("sh",)) == ("bash",), "sh satisfies the bash requirement"


def test_a_windows_target_is_not_offered_a_posix_tool() -> None:
    result = available_for("Windows", True, ("powershell",))
    assert result == (), "this SOC cannot drive a PowerShell session, so it offers nothing"


def test_both_renderer_and_binaries_are_checked() -> None:
    """`pwsh` installed on a POSIX target must not conjure a `powershell` tool."""
    assert available_for("Linux", True, ("bash", "pwsh")) == ("bash",)


def test_unavailability_explains_itself() -> None:
    caps = capabilities_from_output(
        probe_output("Linux", False, ("bash",)), vm="target"
    )
    reasons = caps.as_dict()["unavailable"]
    assert "block_ip" in reasons, "block_ip must be reported as unavailable"
    assert any("sudo -n" in reason for reason in reasons["block_ip"]), reasons["block_ip"]
    assert "powershell" in reasons


def test_an_unreadable_probe_is_an_error_not_an_empty_tool_set() -> None:
    """Returning `()` here would look like a bare machine; it is an unknown machine."""
    for kwargs in ({"stdout": "motd only"}, {"stdout": "", "returncode": 255, "error": "ssh failed"}):
        try:
            capabilities_from_output(vm="target", **kwargs)  # type: ignore[arg-type]
        except CapabilityProbeError:
            pass
        else:
            raise AssertionError(f"capabilities_from_output({kwargs}) must raise")


# ---------------------------------------------------------------------------------------
# The controller: probe once, then obey it
# ---------------------------------------------------------------------------------------
def test_the_controller_probes_the_vm_once_and_caches() -> None:
    driver = FakeDriver(probe_output("Linux", True, ("bash", "iptables")))
    btc = BlueTeamController(driver=driver, default_blue_vm="target")
    first = btc.capabilities()
    second = btc.capabilities(refresh=False)
    assert first is second, "the probe is an SSH round trip; it must not repeat per call"
    assert len(driver.calls) == 1
    btc.capabilities(refresh=True)
    assert len(driver.calls) == 2, "refresh=True must actually re-probe"
    assert driver.calls[0][0] == "target"
    assert driver.calls[0][1] == driver.script, "the catalogue's script is what ran"


def test_supported_tools_comes_from_the_probe() -> None:
    a = BlueTeamController(driver=FakeDriver(probe_output("Linux", True, ("bash", "iptables"))))
    b = BlueTeamController(driver=FakeDriver(probe_output("Linux", True, ("bash",))))
    assert a.supported_tools == ["bash", "block_ip"]
    assert b.supported_tools == ["bash"], "the same code yields a different set per machine"


def test_a_tool_the_target_cannot_run_is_refused_loudly() -> None:
    """A tool the target cannot run must be refused, not rendered: rendering it and
    succeeding would inflate rs_exe."""
    btc = BlueTeamController(driver=FakeDriver(probe_output("Linux", True, ("bash",))))
    try:
        btc.build_command("block_ip", {"ip": "192.168.57.199"})
    except ToolSpecError as exc:
        assert "not available on this target" in str(exc)
    else:
        raise AssertionError("block_ip on a target without iptables must be refused")


def test_a_discovered_tool_still_renders_correctly() -> None:
    btc = BlueTeamController(driver=FakeDriver(probe_output("Linux", True, ("bash", "iptables"))))
    command = btc.build_command("block_ip", {"ip": "192.168.57.199"})
    assert "sudo -n iptables -I INPUT -s 192.168.57.199 -j DROP" in command
    assert "bash" in btc.build_command("bash", {"command": "true"})


def test_probe_capabilities_passes_the_timeout_through() -> None:
    driver = FakeDriver(probe_output("Linux", True, ("bash",)))
    probe_capabilities(driver, "target", timeout_s=7.5)
    assert driver.calls[0][2] == 7.5


if __name__ == "__main__":
    raise SystemExit(run_module_tests(dict(globals())))
