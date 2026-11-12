# SPDX-License-Identifier: Apache-2.0
"""SecLoop SOC server -- the HTTP surface of the Security Orchestration Center.

Endpoints (``docs/INTERFACES.md`` §3)::

    POST /execute_ability   run one round: deploy the whole strategy, attack once,
                            validate, restore the snapshot, release the VM pair
    GET  /health            {"status": "ok", "attack_modes": ["sqli"], "vm_pool_size": 1,
                             "available_pairs": 1, "vagrant_root": "...",
                             "api_version": "1.0", "pre_attack_sample": false,
                             "require_snapshot": true}
    GET  /capabilities      what the blue-team VM can actually run (the source of T_A)
    GET  /pairs             VM pairs and whether they are in use

Request (canonical shape, the whole strategy in one call)::

    {"strategy": [{"tool": "block_ip", "params": {"ip": "192.168.57.199"}}],
     "attack_mode": "sqli", "red_vm": "kali", "blue_vm": "target"}

Legacy shape (one shell command, internally a single ``bash`` tool call)::

    {"command": "iptables -I INPUT -s 192.168.57.199 -j DROP"}

One round, not N rounds
------------------------------------
Fanning a strategy out into one HTTP request per tool would run a full red/blue cycle plus
a snapshot restore for each of them, so a composite strategy would never be evaluated as a
whole.  Here a round is
exactly the sequence in ``docs/INTERFACES.md`` §5: optional pre-attack sample ->
**one** deployment of the entire strategy -> **one** attack against it -> one
``rs_exe``/``rs_attack``/``rs_service`` vector -> snapshot restore.  That timing
lives in :mod:`soc.execution_pipeline`, which imports no Flask and is unit-testable
with fake controllers.

Response invariant
------------------
``feedback`` is non-null **iff** ``success`` is true, and ``success`` means *the
attack was measured*: the strategy was deployed, the attack returned a usable
``[RESULT]`` stage list, the probe ran and the environment was rolled back.  A
round that could not be measured (unparsable/absent ``[RESULT]``, empty stage
list, dead VM, failed snapshot restore) returns ``success: false`` with ``error``
and ``feedback: null``, so no caller can mistake "we could not measure the attack"
for the genuine ``rs_attack = 0.0`` of a successful defence.

A **measured** attack whose stages are all false is a working defence and returns
``success: true`` with ``rs_attack = 0.0``; the additive top-level ``attack_error``
field carries the attack script's own message ("oracle not confirmed" after
``block_ip``, "target unreachable", ...) and ``rs_service`` separates "attack
blocked" (``1``) from "target gone" (``0``).  Business failures use HTTP 200;
capacity exhaustion uses 429 (retry later).

Configuration (environment, all optional)
----------------------------------------
======================================  ==========================================
``SOAR_SOC_HOST`` / ``SOAR_SOC_PORT``   bind address (default ``127.0.0.1:8988``)
``SOAR_VAGRANT_ROOT``                   Vagrant root (default ``<repo>/vagrant``)
``SOAR_VM_POOL``                        JSON array of VM pairs (§3.3)
``SOAR_ABILITY_ENDPOINT``               *client-side* name used by the agent, not read here
``SOC_PRE_ATTACK_SAMPLE``               ``1`` to capture ``pre_attack_stages``
``SOC_REQUIRE_SNAPSHOT``                ``0`` to tolerate a failed snapshot restore
``SOC_LAB_NETWORKS``                    networks the red VM may attack (default
                                        ``192.168.57.0/24,127.0.0.0/8``)
``SOC_ATTACK_MODE``                     default attack mode when a request omits it
                                        (default ``sqli``)
``SOC_BLUE_IP``                         blue-team address used in the lab (default the
                                        INTERFACES §1 target address)
``SOC_POOL_TIMEOUT_S``                  how long a round waits for a free VM pair
                                        (default 300)
``SOC_ATTACK_DELAY_S``                  pause between deploying the strategy and
                                        firing the attack so the defence takes effect
``SOC_ATTACK_TIMEOUT_S``                per-attack budget (default 900)
``SOC_TOOL_TIMEOUT_S``                  per-tool budget (default 60)
``SOC_TARGET_URL``                      rs_service HTTP probe (default the lab anchor)
``SOC_TARGET_MARKER`` / ``SOC_TARGET_MARKER_STRICT``
                                        expected body marker (strict -> rs_service=0)
``SOC_RED_PROBE``                       ``host:port`` reachability probe of the red VM
``SOC_PROBE_TIMEOUT_S``                 probe timeout (default 5)
``SOC_ATTACK_COMMANDS``                 attack registry (default ``soc/attack_commands.json``)
``SOC_LOG_LEVEL`` / ``SOC_LOG_FILE``    logging level / optional rotating log file
======================================  ==========================================

No endpoint, key or credential is hard-coded, and the ``IaCGenerator`` is
deliberately **not** imported or called here: rendering a Vagrantfile does not
create an environment, so a round drives the VMs that ``vagrant up`` actually
started (or fails loudly saying so).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

BATTLEFIELD_DIR = Path(__file__).resolve().parent
if str(BATTLEFIELD_DIR) not in sys.path:
    sys.path.insert(0, str(BATTLEFIELD_DIR))

from flask import Flask, jsonify, request  # noqa: E402
from werkzeug.exceptions import HTTPException  # noqa: E402

from soc.blue_team_controller import BlueTeamController  # noqa: E402
from soc.capability_probe import CapabilityProbeError  # noqa: E402
from soc.execution_pipeline import PipelineConfig, SocRoundPipeline  # noqa: E402
from soc.policy_execution_validator import PolicyExecutionValidator  # noqa: E402
from soc.red_team_controller import RedTeamController  # noqa: E402
from soc.service_probe import ServiceProbe  # noqa: E402
from soc.vagrant_driver import VagrantDriver  # noqa: E402
from soc.vm_pool import VmPool  # noqa: E402

logger = logging.getLogger("soc.server")

SOC_API_VERSION = "1.0"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8988
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"


@dataclass(frozen=True)
class SocConfig:
    """Server-level configuration (round-level switches live in PipelineConfig)."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    log_level: str = "INFO"
    log_file: str | None = None

    @classmethod
    def from_env(cls) -> SocConfig:
        """Read ``SOAR_SOC_*``/``SOC_LOG_*`` with lab defaults."""
        return cls(
            host=os.getenv("SOAR_SOC_HOST", DEFAULT_HOST),
            port=int(os.getenv("SOAR_SOC_PORT", DEFAULT_PORT)),
            log_level=os.getenv("SOC_LOG_LEVEL", "INFO"),
            log_file=os.getenv("SOC_LOG_FILE") or None,
        )


def configure_logging(level: str = "INFO", log_file: str | None = None) -> None:
    """Configure stdlib logging: console always, rotating file optionally.

    Idempotent **and refreshable**. ``create_app()`` configures logging as a side effect of
    being imported, and ``main()`` then calls this again with the parsed
    ``--log-level``/``--log-file``, so the later, more specific request wins: the level is
    always applied, the console handler is created once, and a file handler is added when
    a new path is requested (replacing any previous one so handlers cannot accumulate
    across calls). A flag that is accepted and then does nothing is worse than no flag.
    """
    root = logging.getLogger()
    resolved_level = str(level).strip().upper()
    numeric = getattr(logging, resolved_level, None)
    if not isinstance(numeric, int):
        raise ValueError(
            f"unknown log level {level!r}; use one of "
            f"{', '.join(sorted(logging.getLevelNamesMapping()))}"
        )
    root.setLevel(numeric)
    formatter = logging.Formatter(LOG_FORMAT)

    if not any(getattr(handler, "_secloop_console", False) for handler in root.handlers):
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(formatter)
        setattr(console, "_secloop_console", True)
        root.addHandler(console)

    if log_file:
        path = Path(log_file).expanduser().resolve()
        if getattr(root, "_secloop_log_file", None) != path:
            for handler in list(root.handlers):
                if getattr(handler, "_secloop_log_file", None) is not None:
                    root.removeHandler(handler)
                    handler.close()
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            handler.setFormatter(formatter)
            setattr(handler, "_secloop_log_file", path)
            root.addHandler(handler)
            setattr(root, "_secloop_log_file", path)
            logger.info("SOC: logging to %s", path)


def create_app(
    config: SocConfig | None = None,
    *,
    pool: VmPool | None = None,
    btc: BlueTeamController | None = None,
    rtc: RedTeamController | None = None,
    pev: PolicyExecutionValidator | None = None,
    probe: ServiceProbe | None = None,
    pipeline_config: PipelineConfig | None = None,
) -> Flask:
    """Build the Flask application.

    Every dependency is injectable so the routes can be exercised with fakes.
    With no arguments the real SOC components are constructed from the
    environment.
    """
    settings = config or SocConfig.from_env()
    configure_logging(settings.log_level, settings.log_file)

    driver = VagrantDriver()
    resolved_pool = pool or VmPool.from_env()
    resolved_rtc = rtc or RedTeamController(driver=driver)
    resolved_btc = btc or BlueTeamController(driver=driver)
    resolved_pev = pev or PolicyExecutionValidator()
    resolved_probe = probe or ServiceProbe.from_env()
    pipeline = SocRoundPipeline(
        pool=resolved_pool,
        btc=resolved_btc,
        rtc=resolved_rtc,
        pev=resolved_pev,
        probe=resolved_probe,
        config=pipeline_config or PipelineConfig.from_env(),
    )

    app = Flask(__name__)
    app.json.sort_keys = False
    app.config["SOC_PIPELINE"] = pipeline
    app.config["SOC_POOL"] = resolved_pool
    app.config["SOC_RTC"] = resolved_rtc
    app.config["SOC_DRIVER"] = driver
    app.config["SOC_SETTINGS"] = settings

    logger.info(
        "SOC: ready (api=%s, vagrant_root=%s, pairs=%d, attack_modes=%s)",
        SOC_API_VERSION,
        driver.root,
        resolved_pool.size,
        ", ".join(resolved_rtc.attack_modes) or "none",
    )

    @app.route("/execute_ability", methods=["POST"])
    def execute_ability() -> Any:
        """Run one round of the closed loop (docs/INTERFACES.md §3.1, §5)."""
        payload = request.get_json(silent=True)
        if payload is None and request.data:
            return (
                jsonify(
                    {
                        "success": False,
                        "score": 0.0,
                        "feedback": None,
                        "attack_mode": None,
                        "elapsed_s": 0.0,
                        "error": "request body must be valid JSON",
                    }
                ),
                200,
            )
        body, status = pipeline.execute(payload)
        return jsonify(body), status

    @app.route("/capabilities", methods=["GET"])
    def capabilities() -> Any:
        """Which tools the blue-team VM can run, as far as a probe can tell.

        Paper Eq. 3 defines ``T_A`` as *the tools available in the current environment*,
        so the agent asks the environment instead of assuming. The answer is a
        measurement of the **requirements the catalogue declares** — the OS, whether
        ``sudo -n`` works, and which executables exist — not a promise that every tool
        will then succeed: a present-but-broken ``iptables`` still fails at execution and
        is reported as ``success: false`` there.

        A VM that cannot be probed is an error, never an optimistic or empty tool list.

        Query: ``?vm=<name>`` (optional; defaults to the first pooled pair's blue VM).
        """
        requested = (request.args.get("vm") or "").strip()
        pairs = resolved_pool.pairs_status()
        default_vm = str((pairs[0] or {}).get("blue_vm") or "target") if pairs else "target"
        vm = requested or default_vm
        try:
            caps = resolved_btc.capabilities(vm)
        except (CapabilityProbeError, KeyError, TypeError, ValueError) as exc:
            logger.error("capability probe failed for %s: %s", vm, exc)
            return (
                jsonify(
                    {
                        "vm": vm,
                        "available_tools": None,
                        "error": str(exc),
                        "hint": "the SOC could not probe the VM; T_A must not be guessed",
                    }
                ),
                503,
            )
        return jsonify(caps.as_dict())

    @app.route("/health", methods=["GET"])
    def health() -> Any:
        """Liveness plus the configuration an operator needs to debug a round."""
        return jsonify(
            {
                "status": "ok",
                "attack_modes": resolved_rtc.attack_modes,
                "vm_pool_size": resolved_pool.size,
                "available_pairs": resolved_pool.size - resolved_pool.in_use_count,
                "vagrant_root": str(driver.root),
                "api_version": SOC_API_VERSION,
                "pre_attack_sample": pipeline.config.pre_attack_sample,
                "require_snapshot": pipeline.config.require_snapshot,
            }
        )

    @app.route("/pairs", methods=["GET"])
    def pairs() -> Any:
        """VM pairs and their current occupancy (docs/INTERFACES.md §3.2)."""
        return jsonify({"pairs": resolved_pool.pairs_status()})

    @app.errorhandler(HTTPException)
    def handle_http_exception(exc: HTTPException) -> Any:
        """Keep framework errors (404/405/...) in the API's JSON shape."""
        return (
            jsonify(
                {
                    "success": False,
                    "score": 0.0,
                    "feedback": None,
                    "attack_mode": None,
                    "elapsed_s": 0.0,
                    "error": f"{exc.code} {exc.name}: {exc.description}",
                }
            ),
            exc.code or 500,
        )

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception) -> Any:
        """A bug in the server itself is a 5xx (not a business failure)."""
        logger.exception("SOC: unhandled server error")
        return (
            jsonify(
                {
                    "success": False,
                    "score": 0.0,
                    "feedback": None,
                    "attack_mode": None,
                    "elapsed_s": 0.0,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            ),
            500,
        )

    return app


#: WSGI entry point (``flask --app battlefield/soc_server.py run``).
app = create_app()


def main(argv: list[str] | None = None) -> int:
    """Run the SOC server (threaded, so concurrent rounds share the pool safely)."""
    settings = SocConfig.from_env()
    parser = argparse.ArgumentParser(
        prog="python battlefield/soc_server.py",
        description="SecLoop SOC server: POST /execute_ability, GET /health, GET /pairs.",
    )
    parser.add_argument("--host", default=settings.host, help=f"bind address (default {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=settings.port, help=f"port (default {DEFAULT_PORT})")
    parser.add_argument("--log-level", default=settings.log_level, help="logging level (default INFO)")
    parser.add_argument("--log-file", default=settings.log_file, help="optional rotating log file")
    args = parser.parse_args(argv)

    try:
        configure_logging(args.log_level, args.log_file)
    except ValueError as exc:
        parser.error(str(exc))  # exits 2 with a usage message, rather than ignoring the flag
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        logger.warning(
            "SOC: binding to %s exposes a remote-command endpoint for the lab VMs; "
            "keep it inside an isolated network",
            args.host,
        )
    logger.info("SOC: listening on http://%s:%d/execute_ability", args.host, args.port)
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
