# SPDX-License-Identifier: Apache-2.0
"""Timeout-guarded Vagrant access shared by RTC and BTC.

``python-vagrant`` is the primary transport (the lab is a plain Vagrant +
VMware Workstation environment, see ``vagrant/Vagrantfile``); this module adds
the three things the SOC needs on top of it:

1. **Configurable Vagrant root** -- ``SOAR_VAGRANT_ROOT`` or ``<repo>/vagrant``.
   Nothing in the SOC ever depends on the process working directory.
2. **Fail-loudly availability checks** -- a missing ``Vagrantfile`` or a missing
   ``python-vagrant``/``vagrant`` installation raises a descriptive error
   instead of silently "succeeding".
3. **Watchdogs** -- ``subprocess`` calls made by python-vagrant have no timeout,
   so every call is bounded by a watchdog thread.  A hung ``vagrant ssh`` can
   therefore never wedge the HTTP worker (the orphaned process is logged).

Two API notes, both verified against the ``python-vagrant`` 1.0.0 wheel:

* ``Vagrant.ssh(vm_name, command)`` propagates the **remote exit status** through
  ``subprocess.check_output`` (a non-zero exit raises ``CalledProcessError``
  whose ``output`` holds the remote stdout).  That is what lets BTC distinguish
  a tool that ran from a tool that failed.
* ``Vagrant.snapshot_save/restore/list`` take **no machine name**.  In a two-VM
  environment Vagrant needs ``vagrant snapshot <sub> <vm> <name>``, so this
  module issues the explicit CLI form through the library's command runner.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_VAGRANT_ROOT",
    "SshResult",
    "VagrantCommandTimeout",
    "VagrantDriver",
    "VagrantSnapshotError",
    "VagrantUnavailableError",
]

#: ``<repo>/SecLoop/battlefield/soc/vagrant_driver.py`` -> ``<repo>/SecLoop``
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VAGRANT_ROOT = REPO_ROOT / "vagrant"

VAGRANT_ROOT_ENV = "SOAR_VAGRANT_ROOT"

#: Extra grace on top of the guest-side ``timeout`` before the watchdog fires.
SSH_WATCHDOG_GRACE_S = 120.0
SNAPSHOT_WATCHDOG_S = 900.0
DEFAULT_SSH_TIMEOUT_S = 120.0


class VagrantUnavailableError(RuntimeError):
    """Raised when Vagrant (the CLI, the library or the Vagrantfile) is missing."""


class VagrantCommandTimeout(RuntimeError):
    """Raised when a Vagrant call exceeds its watchdog budget."""


class VagrantSnapshotError(RuntimeError):
    """Raised when a snapshot could not be listed, created or restored.

    Snapshot failures are never swallowed: a round that did not clean up leaves
    the next round measuring a dirty VM, so the caller has to see it.
    """


@dataclass(frozen=True)
class SshResult:
    """Outcome of one ``vagrant ssh`` call."""

    returncode: int
    stdout: str = ""
    error: Optional[str] = None
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """True only when the remote command exited 0 within its budget."""
        return self.returncode == 0 and not self.timed_out


def _default_root() -> Path:
    """Resolve the Vagrant root without ever consulting the working directory."""
    override = os.getenv(VAGRANT_ROOT_ENV)
    if override:
        return Path(override).expanduser()
    return DEFAULT_VAGRANT_ROOT


class VagrantDriver:
    """Thin, watchdog-guarded facade over a Vagrant environment.

    Args:
        root: directory holding ``Vagrantfile``; defaults to
            ``$SOAR_VAGRANT_ROOT`` or ``<repo>/SecLoop/vagrant``.
        ssh_watchdog_grace_s: seconds added to a call's guest-side timeout before
            the host-side watchdog abandons it.
        snapshot_watchdog_s: watchdog budget for snapshot operations.
    """

    def __init__(
        self,
        root: str | os.PathLike[str] | None = None,
        *,
        ssh_watchdog_grace_s: float = SSH_WATCHDOG_GRACE_S,
        snapshot_watchdog_s: float = SNAPSHOT_WATCHDOG_S,
    ) -> None:
        self.root = Path(root).expanduser().resolve() if root else _default_root().resolve()
        self.ssh_watchdog_grace_s = float(ssh_watchdog_grace_s)
        self.snapshot_watchdog_s = float(snapshot_watchdog_s)
        self._vagrant: Any = None
        if not (self.root / "Vagrantfile").is_file():
            logger.warning(
                "VagrantDriver: no Vagrantfile under %s (set %s); "
                "every call will fail until the lab is provisioned",
                self.root,
                VAGRANT_ROOT_ENV,
            )

    # ------------------------------------------------------------------ setup

    def _ensure_ready(self) -> None:
        vagrantfile = self.root / "Vagrantfile"
        if not vagrantfile.is_file():
            raise VagrantUnavailableError(
                f"no Vagrantfile at {vagrantfile}; run `vagrant up` in {self.root} "
                f"or point {VAGRANT_ROOT_ENV} at the directory that holds it"
            )

    @property
    def vagrant(self) -> Any:
        """Lazily construct ``vagrant.Vagrant`` so importing the SOC needs no VM stack."""
        if self._vagrant is None:
            try:
                from vagrant import Vagrant  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover - environment dependent
                raise VagrantUnavailableError(
                    "python-vagrant is required to drive the lab "
                    "(pip install -r requirements/battlefield.txt)"
                ) from exc
            self._vagrant = Vagrant(
                root=str(self.root), quiet_stdout=True, quiet_stderr=True
            )
        return self._vagrant

    # ------------------------------------------------------------- primitives

    def _guarded(self, func: Any, timeout_s: float, what: str) -> Any:
        """Run ``func`` in a daemon thread, abandoning it after ``timeout_s``."""
        box: dict[str, Any] = {}

        def runner() -> None:
            try:
                box["value"] = func()
            except BaseException as exc:  # noqa: BLE001 - re-raised by the caller
                box["exc"] = exc

        thread = threading.Thread(target=runner, name=f"vagrant:{what}", daemon=True)
        thread.start()
        thread.join(timeout_s)
        if thread.is_alive():
            logger.error(
                "vagrant %s exceeded its %.0fs watchdog; abandoning the call "
                "(the orphaned vagrant process may keep running)",
                what,
                timeout_s,
            )
            raise VagrantCommandTimeout(f"{what} exceeded {timeout_s:.0f}s")
        if "exc" in box:
            raise box["exc"]
        return box.get("value")

    def _run(self, args: Sequence[str], timeout_s: float, what: str) -> str:
        """Run a vagrant command and return its stdout (python-vagrant first)."""
        self._ensure_ready()

        def call() -> str:
            runner = getattr(self.vagrant, "_run_vagrant_command", None)
            if runner is not None:
                return str(runner(list(args)))
            return self._run_cli(args)

        return str(self._guarded(call, timeout_s, what))

    def _call(self, args: Sequence[str], timeout_s: float, what: str) -> None:
        """Run a vagrant command discarding its stdout (python-vagrant first)."""
        self._ensure_ready()

        def call() -> None:
            runner = getattr(self.vagrant, "_call_vagrant_command", None)
            if runner is not None:
                runner(list(args))
                return
            self._run_cli(args)

        self._guarded(call, timeout_s, what)

    def _run_cli(self, args: Sequence[str]) -> str:
        """Fallback used only if python-vagrant ever drops its command runner."""
        exe = shutil.which("vagrant")
        if not exe:
            raise VagrantUnavailableError(
                "the `vagrant` executable was not found on PATH"
            )
        logger.debug("VagrantDriver: falling back to the vagrant CLI: %s", list(args))
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [exe, *args],
            cwd=str(self.root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode, [exe, *args], output=completed.stdout
            )
        return completed.stdout

    # ------------------------------------------------------------------- ssh

    def ssh(
        self,
        vm: str,
        command: str,
        timeout_s: float | None = None,
        watchdog_s: float | None = None,
    ) -> SshResult:
        """Run ``command`` on ``vm`` and report its real exit status.

        ``timeout_s`` should match the guest-side ``timeout`` wrapper applied by
        the caller; the host-side watchdog fires ``ssh_watchdog_grace_s`` later,
        so a guest-side timeout normally wins and is reported as exit code 124.
        """
        budget = float(timeout_s or DEFAULT_SSH_TIMEOUT_S)
        watchdog = float(watchdog_s or (budget + self.ssh_watchdog_grace_s))
        logger.debug("vagrant ssh %s (budget %.0fs): %s", vm, budget, command)
        try:
            stdout = self._run(["ssh", vm, "--command", command], watchdog, f"ssh {vm}")
        except VagrantCommandTimeout as exc:
            return SshResult(returncode=124, stdout="", error=str(exc), timed_out=True)
        except subprocess.CalledProcessError as exc:
            stdout = exc.output if isinstance(exc.output, str) else ""
            return SshResult(
                returncode=int(exc.returncode),
                stdout=stdout or "",
                error=f"remote command exited with status {exc.returncode}",
            )
        except VagrantUnavailableError as exc:
            return SshResult(returncode=-1, stdout="", error=str(exc))
        except Exception as exc:  # noqa: BLE001 - python-vagrant raises vagrant.VagrantError
            logger.error("vagrant ssh %s failed: %s", vm, exc)
            return SshResult(returncode=-1, stdout="", error=f"{type(exc).__name__}: {exc}")
        return SshResult(returncode=0, stdout=stdout)

    # -------------------------------------------------------------- snapshots

    def snapshot_list(self, vm: str) -> list[str]:
        """Return the snapshot names of ``vm``.

        Raises:
            VagrantSnapshotError: the list could not be read.  Returning an empty
                list here would let a caller "restore" nothing and carry on with
                a dirty VM, which is a silent failure.
        """
        try:
            output = self._run(
                ["snapshot", "list", vm], self.snapshot_watchdog_s, f"snapshot list {vm}"
            )
        except Exception as exc:  # noqa: BLE001 - normalised below
            raise VagrantSnapshotError(
                f"cannot list snapshots of {vm}: {type(exc).__name__}: {exc}"
            ) from exc

        names: list[str] = []
        for line in output.splitlines():
            candidate = line.strip().lstrip("*").strip()
            if not candidate:
                continue
            lowered = candidate.lower()
            if "no snapshots" in lowered or lowered.startswith("==>"):
                continue
            names.append(candidate)
        return names

    def snapshot_exists(self, vm: str, name: str) -> bool:
        """True when snapshot ``name`` exists on ``vm``."""
        return name in self.snapshot_list(vm)

    def snapshot_save(self, vm: str, name: str) -> None:
        """Create snapshot ``name`` on ``vm`` (also done by ``vagrant/snapshots.sh``).

        Raises:
            VagrantSnapshotError: the snapshot was not created.
        """
        try:
            self._call(
                ["snapshot", "save", vm, name],
                self.snapshot_watchdog_s,
                f"snapshot save {vm} {name}",
            )
        except Exception as exc:  # noqa: BLE001 - normalised below
            raise VagrantSnapshotError(
                f"cannot save snapshot {name!r} on {vm}: {type(exc).__name__}: {exc}"
            ) from exc
        logger.info("snapshot %s saved on %s", name, vm)

    def snapshot_restore(self, vm: str, name: str) -> None:
        """Restore snapshot ``name`` on ``vm``.

        Raises:
            VagrantSnapshotError: the snapshot does not exist or the restore
                command failed.  The caller must not continue a round that could
                not be rolled back.
        """
        names = self.snapshot_list(vm)
        if name not in names:
            raise VagrantSnapshotError(
                f"snapshot {name!r} does not exist on {vm} "
                f"(found: {', '.join(names) if names else 'none'}); "
                f"create it with `bash vagrant/snapshots.sh`"
            )
        try:
            self._call(
                ["snapshot", "restore", vm, name],
                self.snapshot_watchdog_s,
                f"snapshot restore {vm} {name}",
            )
        except Exception as exc:  # noqa: BLE001 - normalised below
            raise VagrantSnapshotError(
                f"cannot restore snapshot {name!r} on {vm}: {type(exc).__name__}: {exc}"
            ) from exc
        logger.info("snapshot %s restored on %s", name, vm)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"VagrantDriver(root={str(self.root)!r})"
