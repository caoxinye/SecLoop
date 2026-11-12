# SPDX-License-Identifier: Apache-2.0
"""SecLoop agent CLI — closed-loop blue-team response (paper §II-B).

Pipeline (every step is real, nothing is simulated):

1. read a **real** Suricata ``fast.log`` and compress it with the shared summariser
   ``S_r`` (``ids/combine_ids_log.py``, INTERFACES §9) into ``C``;
2. assemble the prompt ``P = [C, T_A, E]`` (INTERFACES §8) from ``C``, the tool catalogue
   ``T_A`` (:mod:`agent.tools.security_tools`) and the environment description ``E``;
3. ask the configured OpenAI-compatible endpoint for a threat report and a JSON tool-call
   strategy;
4. deploy the **whole** strategy to the SOC in one ``POST /execute_ability``
   (INTERFACES §3/§5) and print the resulting feedback vector
   (``rs_exe`` / ``rs_attack`` / ``rs_service`` / ``F_i``).

Usage::

    python -m agent.main --ids-summary-file /var/log/suricata/fast.log
    python -m agent.main --ids-summary-file fast.log --dry-run          # strategy only
    python -m agent.main --ids-summary-file fast.log --print-prompt     # P = [C, T_A, E]
    python -m agent.main --check-llm                                    # endpoint self-check
    python -m agent.main --check-soc                                    # SOC /health probe

Exit codes: 0 ok, 2 usage/input, 3 configuration, 4 LLM endpoint, 5 strategy, 6 SOC.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

if __package__ in (None, ""):  # allow `python agent/main.py` as well as `python -m agent.main`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.llm.llm_interface import (  # noqa: E402  (import after the sys.path bootstrap)
    DEFAULT_CONFIG_PATH,
    LLMConfigError,
    LLMEndpointError,
    LLMError,
    LLMResponseError,
    StrategyParseError,
    build_prompt,
    get_llm_client,
    load_config,
)
from agent.tools.batch_executor import (  # noqa: E402
    BatchExecutor,
    SOCError,
    SOCUnavailableError,
)
from agent.tools.security_tools import create_security_tools  # noqa: E402
from agent.tools.tool_manager import StrategyValidationError  # noqa: E402
from battlefield.soc.tool_catalogue import (  # noqa: E402  (repo root is on sys.path above)
    ToolSpecError,
    catalogue_members,
)

logger = logging.getLogger("agent.main")

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_LLM = 4
EXIT_STRATEGY = 5
EXIT_SOC = 6

REPO_ROOT = Path(__file__).resolve().parents[1]
SUMMARIZER_MODULE = "ids.combine_ids_log"
SUMMARIZER_PATH = REPO_ROOT / "ids" / "combine_ids_log.py"


class AgentError(RuntimeError):
    """Invalid CLI input or an unusable alert source."""


# --------------------------------------------------------------------------------------
# Summariser S_r (INTERFACES §9)
# --------------------------------------------------------------------------------------
def _load_summarizer() -> tuple[Callable[..., str] | None, str | None]:
    """Locate ``summarize_fastlog`` from the shared summariser module.

    Tries the normal package import first, then loads ``ids/combine_ids_log.py`` by path.
    Returns ``(None, None)`` when the summariser is unavailable; the caller then decides
    (it must never fabricate alerts).
    """
    try:
        from ids.combine_ids_log import summarize_fastlog  # type: ignore[import-not-found]

        return summarize_fastlog, SUMMARIZER_MODULE
    except ImportError as exc:
        logger.debug("package import of %s failed: %s", SUMMARIZER_MODULE, exc)

    if not SUMMARIZER_PATH.is_file():
        return None, None
    try:
        spec = importlib.util.spec_from_file_location("_secloop_combine_ids_log", SUMMARIZER_PATH)
        if spec is None or spec.loader is None:
            return None, None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - any loader failure is reported, never hidden
        logger.error("cannot load the summariser from %s: %s", SUMMARIZER_PATH, exc)
        return None, None
    function = getattr(module, "summarize_fastlog", None)
    if not callable(function):
        logger.error("%s exposes no callable summarize_fastlog (INTERFACES §9)", SUMMARIZER_PATH)
        return None, None
    return function, str(SUMMARIZER_PATH)


def summarize_alerts(
    summary_file: Path, window_s: int, *, allow_raw_alerts: bool = False
) -> tuple[str, str]:
    """Return ``(C, origin)`` for a real Suricata ``fast.log``.

    ``C`` is defined by paper Eq. 4 as ``S_r(E)`` -- the *compressed* alert summary.  Raw
    Suricata lines are a different quantity (no episode collapsing, no window), so a run
    that silently substituted them would produce prompts that are not comparable with the
    recipe the paper describes.  That substitution is gated behind ``allow_raw_alerts``:
    without it the run fails, and with it the returned ``origin`` states that ``C`` is
    raw -- the "looks configured, means something else" failure the rest of this file
    refuses.

    Args:
        summary_file: a real ``fast.log``.
        window_s: the summariser's episode window (``INTERFACES.md`` §9).
        allow_raw_alerts: diagnostics-only escape hatch.  When true, an unavailable
            summariser falls back to the raw lines and the returned ``origin`` says so.

    Raises:
        AgentError: the file is missing/empty, the summariser returned nothing, or the
            summariser is unavailable and ``allow_raw_alerts`` is false.
    """
    if not summary_file.is_file():
        raise AgentError(f"IDS summary file not found: {summary_file}")

    summarizer, origin = _load_summarizer()
    if summarizer is None:
        if not allow_raw_alerts:
            raise AgentError(
                f"the summariser S_r ({SUMMARIZER_MODULE}, INTERFACES §9) is unavailable, so "
                f"C cannot be computed as paper Eq. 4 defines it (C = S_r(E)). Raw fast.log "
                f"lines are a different quantity -- no episode collapsing, no window -- and "
                f"prompting with them would silently change the experiment. Fix the import, "
                f"or pass --allow-raw-alerts to accept the substitution deliberately."
            )
        logger.error(
            "the summariser S_r (%s, INTERFACES §9) is unavailable; --allow-raw-alerts was "
            "given, so the raw Suricata lines are used as C WITHOUT compression",
            SUMMARIZER_MODULE,
        )
        summary = summary_file.read_text(encoding="utf-8", errors="replace").strip()
        origin = "raw fast.log lines (summariser unavailable; --allow-raw-alerts)"
    else:
        logger.info("summarising %s with %s (window_s=%d)", summary_file, origin, window_s)
        summary = (summarizer(str(summary_file), window_s=window_s) or "").strip()

    if not summary:
        raise AgentError(
            f"{summary_file} yielded an empty alert summary C; refusing to prompt the LLM "
            "without alerts (INTERFACES §9)"
        )
    return summary, origin


# --------------------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------------------
def _declared_tools(config: dict[str, Any], args: argparse.Namespace) -> list[str] | None:
    """Tool names the operator declared explicitly, or ``None`` to discover them.

    Declaring tools is a **claim**, not a measurement, so the result is labelled
    ``tool_source='declared'`` and warned about. The normal path is discovery: paper Eq. 3
    defines ``T_A`` as the tools available in the current environment, and only the
    environment can answer that.
    """
    raw = getattr(args, "tools", None)
    if raw:
        return [part.strip() for part in str(raw).split(",") if part.strip()]
    environment = config.get("environment")
    environment = environment if isinstance(environment, dict) else {}
    configured = environment.get("tools")
    return [str(name) for name in configured] if configured else None


def _resolve_tools(
    config: dict[str, Any],
    args: argparse.Namespace,
    executor: Any,
    *,
    discover: bool = True,
) -> tuple[list[str], str, str]:
    """Return ``(tool_names, tool_source, platform)`` for this run.

    * declared via ``--tools`` / ``environment.tools`` -> ``declared`` (with a warning);
    * otherwise probed from the blue-team VM through ``GET /capabilities`` ->
      ``discovered:<vm>``.

    There is deliberately **no silent fallback** to the full catalogue: guessing ``T_A``
    would let a Linux prompt offer a Windows-only tool that the SOC then "executes"
    through ``bash -lc``.
    """
    declared = _declared_tools(config, args)
    if declared is not None:
        try:
            names = list(catalogue_members(declared))
        except ToolSpecError as exc:
            raise LLMConfigError(str(exc)) from exc
        logger.warning(
            "tool set declared explicitly (%s); this is a claim, not a measurement — "
            "T_A is defined by the environment (paper Eq.3)",
            ", ".join(names),
        )
        environment = config.get("environment")
        environment = environment if isinstance(environment, dict) else {}
        platform = str(
            (args.platform if args.platform is not None else environment.get("platform"))
            or "Linux"
        )
        return names, "declared", platform

    if not discover:  # pragma: no cover - used by callers that never need T_A
        environment = config.get("environment")
        environment = environment if isinstance(environment, dict) else {}
        platform = str(
            (args.platform if args.platform is not None else environment.get("platform"))
            or "Linux"
        )
        return [], "unresolved", platform

    try:
        # Ask about the VM this run will actually deploy to: with a pooled lab the
        # availability answer must describe the same host the commands go to.
        blue_vm = str(executor.vm_config().blue_vm or "") or None
        payload = executor.capabilities(vm=blue_vm)
    except (SOCError, SOCUnavailableError) as exc:
        raise LLMConfigError(
            f"cannot determine the tools available in this environment: {exc}. Start the "
            f"SOC (so `GET /capabilities` can probe the target), or declare the tools "
            f"explicitly with --tools if you accept that this is a claim rather than a "
            f"measurement (paper Eq.3)."
        ) from exc
    names = [str(name) for name in (payload.get("available_tools") or [])]
    if not names:
        raise LLMConfigError(
            "the SOC probed the target and found no usable tool "
            f"({payload.get('unavailable') or payload.get('error') or 'no detail'}); "
            "refusing to build a prompt with an empty T_A"
        )
    platform = str(payload.get("os") or "unknown")
    return names, f"discovered:{payload.get('vm')}", platform


def _environment_from_config(
    config: dict[str, Any],
    tool_manager: Any,
    args: argparse.Namespace,
    *,
    platform: str,
    tool_source: str,
) -> dict[str, Any]:
    environment = config.get("environment")
    environment = environment if isinstance(environment, dict) else {}
    return {
        "platform": platform,
        "tool_source": tool_source,
        "description": (
            args.description
            if args.description is not None
            else str(environment.get("description") or "")
        ),
        "tools": list(tool_manager.get_available_tools()),
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    """Execute the requested CLI action and return a JSON-serialisable result."""
    config = load_config(args.config)
    executor = BatchExecutor()

    # The self-checks must work when the SOC is down (that is when you run them), so
    # they come first and never need `T_A`.
    if args.check_soc:
        health = executor.health_check()
        return {"mode": "check-soc", "endpoint": executor.endpoint, "health": health}

    if args.check_llm:
        client = get_llm_client(config)
        return {"mode": "check-llm", "status": client.check(), "client": client.describe()}

    # From here on a prompt is rendered, so `T_A` has to be resolved from the environment
    # (paper Eq.3) rather than assumed.
    tools, tool_source, platform = _resolve_tools(config, args, executor)
    tool_manager = create_security_tools(executor=executor, available=tools)
    environment = _environment_from_config(
        config, tool_manager, args, platform=platform, tool_source=tool_source
    )

    summary_file = Path(args.ids_summary_file)
    summary, origin = summarize_alerts(
        summary_file, args.window_s, allow_raw_alerts=bool(args.allow_raw_alerts)
    )
    tool_descriptions = tool_manager.get_tool_descriptions()

    if args.print_prompt:
        return {
            "mode": "print-prompt",
            "summary_file": str(summary_file),
            "summary_origin": origin,
            "prompt": build_prompt(
                summary,
                tool_descriptions,
                platform=environment["platform"],
                description=environment["description"],
                available_tools=environment["tools"],
            ),
        }

    client = get_llm_client(config)
    agent_config = config.get("agent")
    agent_config = agent_config if isinstance(agent_config, dict) else {}
    max_tokens = int(args.max_tokens or agent_config.get("max_tokens") or 1024)

    logger.info("generating the threat report")
    threat_report = client.generate_threat_report(summary, max_tokens=max_tokens)

    logger.info("generating the tool-call strategy")
    strategy = client.generate_tool_calls(
        summary,
        tool_manager,
        platform=environment["platform"],
        description=environment["description"],
        available_tools=environment["tools"],
        max_tokens=max_tokens,
    )

    result: dict[str, Any] = {
        "mode": "run",
        "summary_file": str(summary_file),
        "summary_origin": origin,
        "summary": summary,
        "environment": environment,
        "tool_descriptions": tool_descriptions,
        "threat_report": threat_report,
        "strategy": strategy,
        "executed": False,
    }

    if args.dry_run:
        logger.info("--dry-run: strategy generated but not deployed")
        return result

    round_result = tool_manager.execute_strategy(strategy)
    result.update(
        {
            "executed": True,
            "attack_mode": round_result["attack_mode"],
            "soc_endpoint": round_result["endpoint"],
            "soc_success": round_result["success"],
            "soc_error": round_result["error"],
            "elapsed_s": round_result["elapsed_s"],
            "tool_results": round_result["tools"],
            "feedback": round_result["feedback"],
            "rs_exe": round_result["rs_exe"],
            "rs_attack": round_result["rs_attack"],
            "rs_service": round_result["rs_service"],
            "F_i": round_result["F_i"],
        }
    )
    return result


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------
def _emit(text: str = "") -> None:
    sys.stdout.write(f"{text}\n")


def render(result: dict[str, Any]) -> None:
    """Human-readable report on stdout (diagnostics go to logging/stderr)."""
    mode = result.get("mode")
    if mode == "check-llm":
        _emit(result["status"])
        return
    if mode == "check-soc":
        _emit(f"SOC endpoint OK: {result['endpoint']} health={json.dumps(result['health'], ensure_ascii=False)}")
        return
    if mode == "print-prompt":
        _emit(result["prompt"])
        return

    _emit("=== IDS summary (C) ===")
    _emit(f"[source: {result['summary_origin']}]")
    _emit(result["summary"])
    _emit()
    _emit("=== Threat report ===")
    _emit(result["threat_report"])
    _emit()
    _emit("=== Defence strategy (tool calls) ===")
    _emit(json.dumps(result["strategy"], indent=2, ensure_ascii=False))
    _emit()
    if not result["executed"]:
        _emit("(dry run: the strategy was not deployed)")
        return

    _emit(f"=== SOC round ({result['soc_endpoint']}, attack_mode={result['attack_mode']}) ===")
    for index, tool_result in enumerate(result.get("tool_results") or [], start=1):
        if not isinstance(tool_result, dict):
            continue
        status = "ok" if tool_result.get("success") else "FAILED"
        detail = tool_result.get("error") or tool_result.get("output") or ""
        _emit(f"{index}. {tool_result.get('tool')}: {status} {str(detail).strip()[:200]}")
    _emit()
    _emit("=== Feedback vector (INTERFACES §4) ===")
    _emit(f"rs_exe      = {result['rs_exe']}   (mean tool deployment success, Eq.10)")
    _emit(f"rs_attack   = {result['rs_attack']}   (raw attack stage success rate, Eq.11)")
    _emit(f"rs_service  = {result['rs_service']}   (real service probe, {{0,1}}, Eq.12)")
    _emit(f"F_i         = {result['F_i']}   (= rs_exe + rs_attack + rs_service, Eq.13)")
    if result.get("soc_error"):
        _emit(f"soc_error   = {result['soc_error']}")
    if result.get("elapsed_s") is not None:
        _emit(f"elapsed_s   = {result['elapsed_s']}")


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agent.main",
        description="SecLoop blue-team agent: real Suricata alerts -> prompt P=[C,T_A,E] -> "
        "LLM strategy -> one SOC round.",
    )
    parser.add_argument(
        "--ids-summary-file",
        default=None,
        help="path to a real Suricata fast.log (compressed into C by the shared summariser S_r)",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"agent config path (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="generate the threat report and the strategy but do not deploy it to the SOC",
    )
    parser.add_argument(
        "--print-prompt",
        action="store_true",
        help="print the assembled P=[C,T_A,E] prompt and exit (no LLM call, no SOC call)",
    )
    parser.add_argument(
        "--check-llm",
        action="store_true",
        help="run the LLM endpoint self-check (INTERFACES §7.2) and exit",
    )
    parser.add_argument(
        "--check-soc",
        action="store_true",
        help="probe the SOC GET /health endpoint and exit",
    )
    parser.add_argument(
        "--allow-raw-alerts",
        action="store_true",
        help=(
            "diagnostics only: if the summariser S_r is unavailable, use raw fast.log lines "
            "as C instead of failing. C is then NOT paper Eq.4's S_r(E) (INTERFACES §9)"
        ),
    )
    parser.add_argument(
        "--tools",
        default=None,
        help=(
            "comma-separated tool names to DECLARE instead of probing the environment. "
            "`T_A` is defined as the tools available in the current environment (paper "
            "Eq.3), so this is a claim, not a measurement: the result is labelled "
            "tool_source='declared' and warned about. Use it for offline prompt "
            "inspection; the default path asks the SOC via GET /capabilities."
        ),
    )
    parser.add_argument(
        "--platform",
        default=None,
        help=(
            "override the E 'Platform' field (display only). The available-tool set does "
            "NOT come from here — it is probed from the target."
        ),
    )
    parser.add_argument(
        "--description", default=None, help="override the E 'Description' field"
    )
    parser.add_argument(
        "--window-s",
        type=int,
        default=300,
        help="summariser aggregation window in seconds (INTERFACES §9, default 300)",
    )
    parser.add_argument("--max-tokens", type=int, default=None, help="max tokens per LLM call")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the whole result as JSON instead of the human-readable report",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging level (default: INFO)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    actionable = args.check_llm or args.check_soc or bool(args.ids_summary_file)
    if not actionable:
        parser.print_help(sys.stderr)
        sys.stderr.write("\nerror: --ids-summary-file is required (or use --check-llm/--check-soc)\n")
        return EXIT_USAGE

    try:
        result = run(args)
    except LLMConfigError as exc:
        logger.error("LLM endpoint is not configured: %s", exc)
        return EXIT_CONFIG
    except LLMEndpointError as exc:
        logger.error("LLM endpoint failure: %s", exc)
        return EXIT_LLM
    except (StrategyParseError, LLMResponseError) as exc:
        logger.error("the model answer could not be turned into a strategy: %s", exc)
        return EXIT_STRATEGY
    except StrategyValidationError as exc:
        logger.error("the generated strategy violates INTERFACES §6: %s", exc)
        return EXIT_STRATEGY
    except SOCUnavailableError as exc:
        logger.error("SOC round failed: %s", exc)
        return EXIT_SOC
    except SOCError as exc:
        logger.error("SOC request rejected: %s", exc)
        return EXIT_SOC
    except AgentError as exc:
        logger.error("%s", exc)
        return EXIT_USAGE
    except LLMError as exc:  # any remaining LLM failure stays explicit
        logger.error("LLM failure: %s", exc)
        return EXIT_LLM
    except OSError as exc:
        logger.error("I/O failure: %s", exc)
        return EXIT_USAGE

    if args.json:
        _emit(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        render(result)
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(main())
