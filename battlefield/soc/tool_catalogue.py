# SPDX-License-Identifier: Apache-2.0
"""The SecLoop tool catalogue — the **only** tool table in the repository.

What a tool *is* lives here. What is *available* is discovered from the target at run
time (`soc.capability_probe`), because the paper's Eq. 3 defines ``T_A`` as the tools
available **in the current environment**.

Why this is not a per-OS list
-----------------------------
Hard-coding ``platforms={"Linux"}`` / ``{"Windows"}`` per
tool and filtering by a configured platform string swaps one bad assumption (a config file
offering ``powershell`` while ``platform`` says ``Linux``) for another: a table claiming to
know what a machine can do. It cannot. A box may lack
``iptables``; a privileged tool is useless without working ``sudo``; and the machine may
not be the OS the config claims.

So each entry declares the **requirements to detect** and the **interpreter** it needs,
and the SOC probes the target:

* ``requires_any`` — at least one of these executables must exist on the target;
* ``requires_root`` — plus ``sudo -n`` must actually work there;
* ``renderer`` — which command interpreter the tool needs (``posix`` shell or a
  PowerShell session). The SOC declares the renderers it can drive, so a tool whose
  renderer it cannot drive is unavailable no matter what is installed.

Nothing here decides availability. :func:`names_from_capabilities` does, from probe
results.

Why one table
-------------
``docs/INTERFACES.md`` §6 has one implementation here, and every consumer derives from
it: the registry in ``agent/tools/security_tools.py`` (names, descriptions, and the
*human-readable* ``command`` such as ``"<command>"``) and the executable format string
``"{command}"`` the SOC renders.  Hand-kept copies drift: a table can offer
``powershell`` on a target whose prompt says ``Platform: Linux``, and the SOC would
render it through ``bash -lc``, so the call *succeeded* and credited a defence that
never happened.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shlex
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

logger = logging.getLogger(__name__)

__all__ = [
    "BINARY_MARKER",
    "CATALOGUE_BY_NAME",
    "DEFAULT_TOOL_TIMEOUT_S",
    "OS_MARKER",
    "RENDERERS",
    "ROOT_MARKER",
    "SOC_RENDERERS",
    "TOOL_CATALOGUE",
    "TOOL_NAMES",
    "ToolParameter",
    "ToolSpec",
    "ToolSpecError",
    "build_command",
    "catalogue_members",
    "detection_script",
    "detection_targets",
    "documented_command",
    "is_available",
    "names_from_capabilities",
    "render_tool_descriptions",
    "renderer_for_os",
    "spec_for",
    "unavailable_reasons",
]

#: Command interpreters a tool may need.
RENDERERS = frozenset({"posix", "powershell"})
#: Renderers *this* SOC can drive. Vagrant SSH gives a POSIX shell, so a tool needing a
#: PowerShell session is unavailable here even on a Windows guest — recorded as a
#: capability rather than asserted as a platform tag.
SOC_RENDERERS = frozenset({"posix"})
#: ``docs/INTERFACES.md`` §6: guest-side budget per tool (``SOC_TOOL_TIMEOUT_S``).
DEFAULT_TOOL_TIMEOUT_S = 60.0

#: Probe output markers. The detection script prints these; the parser reads them.
OS_MARKER = "__SECLOOP_OS__"
ROOT_MARKER = "__SECLOOP_ROOT__"
BINARY_MARKER = "__SECLOOP_BIN__"


class ToolSpecError(ValueError):
    """A tool call cannot be rendered: unknown tool, unmet requirement, bad parameter."""


@dataclass(frozen=True)
class ToolParameter:
    """One declared parameter, as it appears in ``T_A``."""

    name: str
    type: str = "string"
    required: bool = True


@dataclass(frozen=True)
class ToolSpec:
    """One entry of the shared catalogue.

    Args:
        name: canonical tool name (§6).
        description: one sentence, used verbatim in ``T_A``.
        parameters: declared parameters, in the order ``T_A`` lists them.
        template: the shell format string the SOC renders (``{param}`` placeholders).
            The human-readable form is *derived* by :meth:`documented_command`.
        privileged: needs root on the blue-team VM, so the SOC prefixes ``sudo -n``.
        renderer: the interpreter needed to run it (``posix`` or ``powershell``).
        requires_any: executables to look for on the target; at least one must exist.
            Empty means the tool needs nothing beyond its renderer.
        requires_root: also require that ``sudo -n`` works on the target.
    """

    name: str
    description: str
    parameters: tuple[ToolParameter, ...] = ()
    template: str = ""
    privileged: bool = False
    renderer: str = "posix"
    requires_any: tuple[str, ...] = ()
    requires_root: bool = False

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ToolSpecError("a catalogue entry needs a non-empty name")
        if self.renderer not in RENDERERS:
            raise ToolSpecError(
                f"tool {self.name!r} declares renderer {self.renderer!r}; "
                f"known renderers: {sorted(RENDERERS)}"
            )
        if not self.template:
            raise ToolSpecError(f"tool {self.name!r} needs a template")

    # ------------------------------------------------------------------ derived
    def documented_command(self) -> str:
        """The §6 "执行的命令" form: ``{ip}`` becomes ``<ip>``.

        Derived from :attr:`template` on purpose: a hand-written documentation string
        would describe the same command twice, and the two forms drift apart
        (``"<command>"`` vs ``"{command}"``).
        """
        return documented_command(self.template)

    def required_parameters(self) -> tuple[str, ...]:
        """Names of the parameters marked required, in declaration order."""
        return tuple(p.name for p in self.parameters if p.required)

    def parameter(self, name: str) -> ToolParameter | None:
        for declared in self.parameters:
            if declared.name == name:
                return declared
        return None

    def unmet_requirements(
        self, *, renderer: str, binaries: Iterable[str], root_available: bool
    ) -> tuple[str, ...]:
        """Why this tool is unavailable in a probed environment (empty = available)."""
        missing: list[str] = []
        if self.renderer != renderer:
            missing.append(f"needs a {self.renderer} session, target offers {renderer}")
        if self.requires_any:
            present = set(binaries)
            if not any(binary in present for binary in self.requires_any):
                missing.append(f"none of {list(self.requires_any)} is on the target")
        if self.requires_root and not root_available:
            missing.append("needs root and `sudo -n` does not work on the target")
        return tuple(missing)


#: The catalogue. Order is the §6 order and the order ``T_A`` lists tools in.
TOOL_CATALOGUE: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="block_ip",
        description="Block an IP address using iptables",
        parameters=(ToolParameter("ip", "string", True),),
        template="iptables -I INPUT -s {ip} -j DROP",
        privileged=True,
        renderer="posix",
        requires_any=("iptables",),
        requires_root=True,
    ),
    ToolSpec(
        name="bash",
        description="Execute a shell command on the blue-team target",
        parameters=(ToolParameter("command", "string", True),),
        template="{command}",
        privileged=False,
        renderer="posix",
        requires_any=("bash", "sh"),
    ),
    ToolSpec(
        name="powershell",
        description="Execute a PowerShell command (Windows targets only)",
        parameters=(ToolParameter("command", "string", True),),
        template="{command}",
        privileged=False,
        renderer="powershell",
        requires_any=("pwsh", "powershell.exe", "powershell"),
    ),
)

CATALOGUE_BY_NAME: dict[str, ToolSpec] = {spec.name: spec for spec in TOOL_CATALOGUE}
#: Tool names in §6 order — also the ``E`` section's "Available tools" order.
TOOL_NAMES: tuple[str, ...] = tuple(spec.name for spec in TOOL_CATALOGUE)

if len(CATALOGUE_BY_NAME) != len(TOOL_CATALOGUE):  # pragma: no cover - import-time guard
    raise ToolSpecError("the tool catalogue contains duplicate names")


# ---------------------------------------------------------------------------------------
# Lookup and rendering
# ---------------------------------------------------------------------------------------
def spec_for(name: Any) -> ToolSpec:
    """The catalogue entry for ``name``.

    Raises:
        ToolSpecError: the name is unknown.
    """
    text = "" if name is None else str(name).strip()
    spec = CATALOGUE_BY_NAME.get(text)
    if spec is None:
        raise ToolSpecError(
            f"unsupported tool {text!r}; supported tools: {', '.join(sorted(CATALOGUE_BY_NAME))}"
        )
    return spec


def catalogue_members(names: Sequence[Any]) -> tuple[str, ...]:
    """Check a declared tool list against the catalogue (**membership only**).

    Availability is a property of a *probed environment*, not of this table, so it is
    checked by the caller against :func:`names_from_capabilities`.

    Raises:
        ToolSpecError: a name is not in the catalogue.
    """
    return tuple(spec_for(raw).name for raw in names)


def documented_command(template: str) -> str:
    """Turn a format string into its §6 documentation form (``{x}`` -> ``<x>``)."""
    return re.sub(r"\{(\w+)\}", r"<\1>", str(template))


def renderer_for_os(os_name: Any, *, default: str = "posix") -> str:
    """Map a probed OS name to the interpreter family.

    Only a genuine Windows answer maps to ``powershell``. ``MINGW64_NT-…``, ``MSYS_NT-…``
    and ``CYGWIN_NT-…`` are **POSIX** shells running on Windows: the probe script printing
    its markers at all is proof that a POSIX shell ran it, so treating those as
    ``powershell`` would let an inference override a direct observation.

    An unknown or empty answer returns ``default`` instead of guessing a specific OS.
    """
    text = ("" if os_name is None else str(os_name)).strip().lower()
    if not text or text == "unknown":
        return default
    if text.startswith(("mingw", "msys", "cygwin")):
        return "posix"
    if "windows" in text:
        return "powershell"
    return "posix"


# ---------------------------------------------------------------------------------------
# Capability detection (the probe script is *derived* from the catalogue)
# ---------------------------------------------------------------------------------------
def detection_targets() -> tuple[str, ...]:
    """Every executable the catalogue cares about, sorted and de-duplicated."""
    wanted: set[str] = set()
    for spec in TOOL_CATALOGUE:
        wanted.update(spec.requires_any)
    return tuple(sorted(wanted))


def detection_script() -> str:
    """A POSIX shell script reporting the target's OS, root access and binaries.

    One round trip, and every value is *observed* rather than assumed. The binary list
    comes from :func:`detection_targets`, so the probe cannot fall behind the catalogue.
    Always exits 0: a missing binary is information, not an error.
    """
    checks = "\n".join(
        f"command -v {shlex.quote(name)} >/dev/null 2>&1 && "
        f"printf '{BINARY_MARKER} %s\\n' {shlex.quote(name)}"
        for name in detection_targets()
    )
    return (
        f"printf '{OS_MARKER} %s\\n' \"$(uname -s 2>/dev/null || echo unknown)\"\n"
        f"if sudo -n true >/dev/null 2>&1; then printf '{ROOT_MARKER} 1\\n'; "
        f"else printf '{ROOT_MARKER} 0\\n'; fi\n"
        f"{checks}\n"
        "exit 0"
    )


def is_available(*args: Any, **kwargs: Any) -> bool:  # pragma: no cover - not supported
    """Not supported. Use :func:`names_from_capabilities`, which applies **both** gates.

    The target's requirements are not the whole question: this SOC can only drive a
    ``posix`` session, so ``powershell`` is unavailable on a Windows target even when
    ``pwsh`` is installed::

        names_from_capabilities(renderer="powershell", binaries={"pwsh"}, root_available=True)    # ()

    One question, one predicate: this name refuses to answer.
    """
    raise ToolSpecError(
        "is_available() is not supported: it skips the SOC renderer gate and contradicts "
        "names_from_capabilities(). Use names_from_capabilities(renderer=..., "
        "binaries=..., root_available=...)."
    )


def names_from_capabilities(
    *,
    renderer: str,
    binaries: Iterable[str],
    root_available: bool,
    soc_renderers: Iterable[str] = SOC_RENDERERS,
) -> tuple[str, ...]:
    """The tool names ``T_A`` may offer, in §6 order, for a **probed** environment.

    Two gates, both observed rather than assumed:
    this SOC must be able to **drive** the tool's interpreter (``soc_renderers``), and the
    **target** must satisfy the tool's requirements. This — not a stored platform tag — is
    what makes ``T_A`` "the tools available in the current environment" (paper Eq. 3).
    """
    found = set(binaries)
    drivable = set(soc_renderers)
    return tuple(
        spec.name
        for spec in TOOL_CATALOGUE
        if spec.renderer in drivable
        and not spec.unmet_requirements(
            renderer=renderer, binaries=found, root_available=root_available
        )
    )


def unavailable_reasons(
    *,
    renderer: str,
    binaries: Iterable[str],
    root_available: bool,
    soc_renderers: Iterable[str] = SOC_RENDERERS,
) -> dict[str, tuple[str, ...]]:
    """``name -> why it is missing`` for every unavailable entry (for HTTP responses)."""
    found = set(binaries)
    drivable = set(soc_renderers)
    reasons: dict[str, tuple[str, ...]] = {}
    for spec in TOOL_CATALOGUE:
        unmet = list(
            spec.unmet_requirements(
                renderer=renderer, binaries=found, root_available=root_available
            )
        )
        # The target might be able to run it while *this* SOC cannot drive it. Reporting
        # only the target-side reason would read as "the machine is fine, so why not?".
        if spec.renderer not in drivable and spec.renderer == renderer:
            unmet.append(
                f"this SOC cannot drive a {spec.renderer} session "
                f"(it drives {sorted(drivable)})"
            )
        if unmet:
            reasons[spec.name] = tuple(unmet)
    return reasons


# ---------------------------------------------------------------------------------------
# Command rendering (the SOC's implementation, shared so it cannot diverge)
# ---------------------------------------------------------------------------------------
def build_command(
    name: Any,
    params: Mapping[str, Any] | None = None,
    *,
    available: Iterable[str] | None = None,
    renderer: str = "posix",
    tool_timeout_s: float = DEFAULT_TOOL_TIMEOUT_S,
) -> str:
    """Render the guest-side shell command for one tool call.

    Args:
        name: tool name, e.g. ``block_ip``.
        params: tool parameters.
        available: the tools **discovered** on the target. When given, a tool outside it
            is refused: an environment that cannot run a tool must never appear to run it.
        renderer: the interpreter family driving the target.
        tool_timeout_s: guest-side budget, wrapped as ``timeout``.

    Returns:
        One shell command, wrapped in ``timeout`` + ``bash -lc``.

    Raises:
        ToolSpecError: unknown tool, not available on the target, wrong renderer, or a
            missing/invalid parameter.
    """
    spec = spec_for(name)

    # This SOC can only drive a POSIX session; a renderer it cannot drive must never be
    # rendered, whatever the caller passes. Without this the shared renderer would
    # happily wrap a PowerShell command in `bash -lc`.
    if renderer not in SOC_RENDERERS:
        raise ToolSpecError(
            f"this SOC drives {sorted(SOC_RENDERERS)}; refusing to render for a {renderer!r} "
            f"session (tool {spec.name!r})"
        )
    if spec.renderer != renderer:
        raise ToolSpecError(
            f"tool {spec.name!r} needs a {spec.renderer} session but this runner drives "
            f"{renderer}; it is never offered in T_A here"
        )
    if available is not None:
        offered = set(available)
        if spec.name not in offered:
            raise ToolSpecError(
                f"tool {spec.name!r} is not available on this target; discovered tools: "
                f"{', '.join(sorted(offered)) or 'none'}"
            )

    if params is None:
        params = {}
    if not isinstance(params, Mapping):
        raise ToolSpecError(
            f"params for tool {spec.name!r} must be an object, got {type(params).__name__}"
        )

    values: dict[str, Any] = dict(params)
    if spec.name == "block_ip" and "ip" not in values and "ip_address" in values:
        # Tolerant alias; the contract says `ip`.
        logger.warning(
            "tool_catalogue: block_ip received the legacy parameter 'ip_address'; "
            "the frozen contract (docs/INTERFACES.md §6) uses 'ip'"
        )
        values["ip"] = values["ip_address"]

    for key in spec.required_parameters():
        value = values.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ToolSpecError(f"tool {spec.name!r} requires parameter {key!r}")
        if not isinstance(value, str):
            raise ToolSpecError(
                f"tool {spec.name!r} parameter {key!r} must be a string, "
                f"got {type(value).__name__}"
            )
        if "\x00" in value:
            raise ToolSpecError(f"tool {spec.name!r} parameter {key!r} contains a NUL byte")

    if spec.name == "block_ip":
        ip_value = str(values["ip"]).strip()
        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError as exc:
            raise ToolSpecError(f"block_ip received an invalid IP address: {ip_value!r}") from exc
        if address.version != 4:
            raise ToolSpecError(f"block_ip expects an IPv4 address, got {ip_value!r}")
        values["ip"] = str(address)

    try:
        command = spec.template.format(**values)
    except (KeyError, IndexError) as exc:
        raise ToolSpecError(f"cannot render tool {spec.name!r}: {exc}") from exc

    if spec.privileged:
        command = f"sudo -n {command}"
    return (
        f"timeout --signal=TERM --kill-after=5 {float(tool_timeout_s):.0f} "
        f"bash -lc {shlex.quote(command)}"
    )


def render_tool_descriptions(specs: Iterable[ToolSpec] = TOOL_CATALOGUE) -> str:
    """Render the ``T_A`` text (paper Eq. 3) from catalogue entries.

    Format, one line per tool::

        - block_ip: Block an IP address using iptables. Parameters: ip (string, required)
    """
    lines: list[str] = []
    for spec in specs:
        description = spec.description.strip()
        if description and not description.endswith((".", "!", "?")):
            description += "."
        params = ", ".join(
            f"{p.name} ({p.type}, {'required' if p.required else 'optional'})"
            for p in spec.parameters
        )
        line = f"- {spec.name}: {description}"
        if params:
            line += f" Parameters: {params}"
        lines.append(line)
    return "\n".join(lines)
