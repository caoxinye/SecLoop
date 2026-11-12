# SPDX-License-Identifier: Apache-2.0
"""Drift guards for values that live in more than one place.

Every constant here is written down two or three times because it is needed on both
sides of a process boundary (the SOC server, the red VM, the agent).  Duplication is
sometimes unavoidable; *silent* divergence is not.  These tests are the seam that
turns a divergence into a red test.

Each pair below must agree, and a mismatch is a red test:

* ``sqli_lab.DEFAULT_DELAY_S`` and the SOC registry's ``--delay``: the standalone probe
  must run the same experiment as the SOC-driven one;
* ``sqli_lab.DEFAULT_TIMEOUT_S`` and the registry's ``request_timeout_s``.

Standard library only: no VM, no network, no Suricata.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _labkit  # noqa: E402  (path bootstrap must come first)
from _labkit import REPO_ROOT, SQLI_LAB_PATH, run_module_tests  # noqa: E402

REGISTRY_PATH = REPO_ROOT / "battlefield" / "soc" / "attack_commands.json"
RTC_PATH = REPO_ROOT / "battlefield" / "soc" / "red_team_controller.py"
PIPELINE_PATH = REPO_ROOT / "battlefield" / "soc" / "execution_pipeline.py"
VM_POOL_PATH = REPO_ROOT / "battlefield" / "soc" / "vm_pool.py"
BATCH_EXECUTOR_PATH = REPO_ROOT / "agent" / "tools" / "batch_executor.py"
REQUIREMENTS_DIR = REPO_ROOT / "requirements"


def module_literal(path: Path, name: str):
    """Return the literal assigned to ``name`` at module level in ``path``.

    Read through ``ast`` rather than by importing: the attack script needs
    ``requests`` and the SOC modules sit next to ``python-vagrant``, neither of which
    the lab suite may depend on.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return ast.literal_eval(node.value)
    raise AssertionError(f"no module-level {name} in {path}")


def load_registry() -> dict:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def registry_attack_modes() -> list[str]:
    """Registry keys that are attack modes (the file also carries ``_``-prefixed notes)."""
    return sorted(key for key in load_registry() if not key.startswith("_"))


# ---------------------------------------------------------------------------------------
# The attack probe's timing must mean the same thing in all three places
# ---------------------------------------------------------------------------------------
def test_registry_delay_matches_the_script_default():
    registry = load_registry()["sqli"]["delay_s"]
    script = module_literal(SQLI_LAB_PATH, "DEFAULT_DELAY_S")
    assert float(registry) == float(script), (
        f"attack_commands.json pins --delay {registry} but sqli_lab.py defaults to "
        f"{script}: the standalone probe would run a different experiment"
    )


def test_registry_timeout_matches_the_script_default():
    registry = load_registry()["sqli"]["request_timeout_s"]
    script = module_literal(SQLI_LAB_PATH, "DEFAULT_TIMEOUT_S")
    assert float(registry) == float(script), (
        f"attack_commands.json pins --timeout {registry} but sqli_lab.py defaults to "
        f"{script}"
    )


def test_the_rtc_inline_fallbacks_match_the_registry():
    """``red_team_controller`` re-states both values as ``entry.get(key, <literal>)``.

    The registry supplies them, so the fallbacks are only reachable when a future
    registry entry omits a key -- which is exactly when a stale literal would go
    unnoticed.
    """
    source = RTC_PATH.read_text(encoding="utf-8")
    delay = re.search(r'"delay_s":\s*entry\.get\(\s*"delay_s"\s*,[^,]*,\s*([0-9.]+)\s*\)', source)
    timeout = re.search(
        r'"request_timeout_s":\s*entry\.get\(\s*"request_timeout_s"\s*,\s*([0-9.]+)\s*\)',
        source,
    )
    assert delay, "could not find the delay_s fallback in red_team_controller.py"
    assert timeout, "could not find the request_timeout_s fallback in red_team_controller.py"

    registry = load_registry()["sqli"]
    assert float(delay.group(1)) == float(registry["delay_s"])
    assert float(timeout.group(1)) == float(registry["request_timeout_s"])


def test_the_delay_is_below_the_request_timeout():
    """A per-request timeout at or below the SLEEP threshold cannot resolve the test."""
    assert module_literal(SQLI_LAB_PATH, "DEFAULT_TIMEOUT_S") > module_literal(
        SQLI_LAB_PATH, "DEFAULT_DELAY_S"
    )


# ---------------------------------------------------------------------------------------
# The attack mode default must mean the same thing on both sides of the wire
# ---------------------------------------------------------------------------------------
def test_attack_mode_defaults_agree_everywhere():
    """The agent, the SOC pipeline, the VM pool and the registry all say "sqli".

    The two processes read *different* environment variables on purpose
    (``SOAR_ATTACK_MODE`` for the agent, ``SOC_ATTACK_MODE`` for the server), so the
    only thing that can be checked statically is that the built-in default -- the
    value used when nobody sets anything -- is the same on both sides.
    """
    registry_modes = registry_attack_modes()
    pipeline = PIPELINE_PATH.read_text(encoding="utf-8")
    pool = module_literal(VM_POOL_PATH, "DEFAULT_ATTACK_MODE")
    agent = module_literal(BATCH_EXECUTOR_PATH, "DEFAULT_ATTACK_MODE")

    assert pool == "sqli"
    assert agent == "sqli"
    assert registry_modes == ["sqli"], (
        f"the SOC registry offers {registry_modes}; INTERFACES §1 freezes the lab to sqli"
    )
    assert 'os.getenv("SOC_ATTACK_MODE", "sqli")' in pipeline, (
        "the SOC pipeline's attack-mode default moved or changed; the agent's "
        "SOAR_ATTACK_MODE default must stay the same value"
    )


def test_the_agent_only_advertises_attack_modes_the_registry_has():
    """The client's hard-coded set must not promise a mode the SOC cannot run."""
    supported = module_literal(BATCH_EXECUTOR_PATH, "SUPPORTED_ATTACK_MODES")
    assert set(supported) <= set(registry_attack_modes()), (
        f"the agent advertises {supported} but the SOC registry only has "
        f"{registry_attack_modes()}"
    )


VAGRANTFILE_PATH = REPO_ROOT / "vagrant" / "Vagrantfile"
IAC_GENERATOR_PATH = REPO_ROOT / "battlefield" / "soc" / "iac_generator.py"


def test_the_vagrantfile_and_the_iac_defaults_agree_on_resources():
    """Two independent definitions of the same VM sizes; they must not drift.

    ``iac_generator`` renders a Vagrantfile for another VM pair, so its ``memory`` /
    ``cpus`` defaults describe the same machines as ``vagrant/Vagrantfile``. Nothing
    forces that agreement, and these numbers are exactly the kind of thing that
    gets bumped in one place only.
    """
    vagrantfile = VAGRANTFILE_PATH.read_text(encoding="utf-8")
    sizes = sorted(int(m) for m in re.findall(r"v\.memory\s*=\s*(\d+)", vagrantfile))
    cpus = sorted(int(m) for m in re.findall(r"v\.cpus\s*=\s*(\d+)", vagrantfile))
    assert sizes, "no `v.memory = ...` assignments found in the Vagrantfile"

    source = IAC_GENERATOR_PATH.read_text(encoding="utf-8")
    iac_sizes = sorted(int(m) for m in re.findall(r'"memory":\s*(\d+)', source))
    iac_cpus = sorted(int(m) for m in re.findall(r'"cpus":\s*(\d+)', source))
    assert (sizes, cpus) == (iac_sizes, iac_cpus), (
        f"Vagrantfile {sizes}MB/{cpus}cpu vs iac_generator {iac_sizes}MB/{iac_cpus}cpu"
    )


# ---------------------------------------------------------------------------------------
# Dependency manifests: the documented commands must actually be installable
# ---------------------------------------------------------------------------------------
def pinned_requests_versions() -> dict[str, str]:
    """Exact ``requests==`` pins, keyed by manifest file name."""
    manifests = [
        REQUIREMENTS_DIR / "battlefield.txt",
        REPO_ROOT / "agent" / "requirements.txt",
    ]
    pins: dict[str, str] = {}
    for path in manifests:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("requests=="):
                pins[path.name] = stripped.split("==", 1)[1].strip()
    return pins


def test_exact_requests_pins_agree():
    """Two different exact pins made the HTTP stack depend on install order."""
    pins = pinned_requests_versions()
    assert pins, "no exact `requests==` pin found; the manifests changed shape"
    assert len(set(pins.values())) == 1, (
        f"conflicting exact requests pins across subsystems: {pins}"
    )


def test_pytest_is_declared_in_a_manifest():
    """The only self-check in the repo is `pytest`, and no runtime manifest has it."""
    manifest = REQUIREMENTS_DIR / "test.txt"
    assert manifest.is_file(), (
        "docs/quickstart.md section 7 runs `python -m pytest -q`, but no manifest "
        "declares pytest; add requirements/test.txt"
    )
    assert re.search(r"^pytest", manifest.read_text(encoding="utf-8"), re.MULTILINE), (
        f"{manifest.name} exists but does not require pytest"
    )


def test_quickstart_tells_the_reader_to_install_the_test_manifest():
    quickstart = (REPO_ROOT / "docs" / "quickstart.md").read_text(encoding="utf-8")
    assert "requirements/test.txt" in quickstart, (
        "quickstart runs pytest without telling the reader where pytest comes from"
    )


if __name__ == "__main__":
    raise SystemExit(run_module_tests(dict(globals())))
