# SPDX-License-Identifier: Apache-2.0
"""Training-side utilities.

Sub-modules that mirror agent-owned code (tool registry, SOC transport, LLM judge)
are re-exports only - see ``INTERFACES.md`` §6 and §7.

The names below are resolved lazily (PEP 562).  ``model_utils`` and
``sa_grpo_trainer`` need ``transformers``/``trl``, while ``llm_judge`` and the three
re-export modules need only the sibling ``agent`` package.  Importing them eagerly
would make the reward-only code path depend on the whole training stack -- and the
self-check that has to stay cheap is the client's own, not this package's
(``python -m agent.llm.llm_interface --check``, INTERFACES.md §7.2) -- so nothing is
imported until it is asked for.
"""

from __future__ import annotations

import importlib
from typing import Any, Dict, Tuple

_LAZY_ATTRS: Dict[str, Tuple[str, str]] = {
    "SAGRPOMisconfigurationError": (".sa_grpo_trainer", "SAGRPOMisconfigurationError"),
    "SAGRPOTrainer": (".sa_grpo_trainer", "SAGRPOTrainer"),
    "Summarizer": (".summarizer", "Summarizer"),
    "get_tokenizer": (".model_utils", "get_tokenizer"),
    "validate_sa_grpo_config": (".sa_grpo_trainer", "validate_sa_grpo_config"),
}

__all__ = sorted(_LAZY_ATTRS)


def __getattr__(name: str) -> Any:
    """Resolve the re-exported names on first access."""
    try:
        module_name, attribute = _LAZY_ATTRS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(importlib.import_module(module_name, __package__), attribute)
    globals()[name] = value
    return value


def __dir__() -> list:
    return sorted(set(globals()) | set(_LAZY_ATTRS))
