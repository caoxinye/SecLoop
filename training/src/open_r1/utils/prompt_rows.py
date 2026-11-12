# SPDX-License-Identifier: Apache-2.0
"""Per-row environment resolution for the training prompt.

Paper Eq. 3 defines ``T_A`` as the tools available **in the current environment**. On the
evaluation path that environment is probed live (``GET /capabilities``). During training
there is no live VM, so the environment has to come from the corpus that recorded it — and
it must be read from the *same* row that supplies the ``E`` section, or the two sections
can disagree about what the model is allowed to call.

Why this is not just "use the whole catalogue"
----------------------------------------------
Rendering the training prompt's ``T_A`` from the full catalogue produces exactly that
inconsistency: on the shipped Linux lab it advertises ``powershell`` next to
``Platform: Linux``, and the reward then has to score a call the environment could never
run. Reading the row instead is offline, per-row, and makes ``T_A`` and ``E`` consistent by
construction.

These helpers live here rather than in ``grpo.py`` so they can be tested without
``torch``/``trl``/``datasets``, which the rest of the trainer needs.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from open_r1._syspath import ensure_repo_root_on_path

ensure_repo_root_on_path()

from battlefield.soc.tool_catalogue import catalogue_members  # noqa: E402

__all__ = ["REQUIRED_COLUMNS", "resolve_row_tools", "resolve_row_environment", "validate_corpus_schema"]

#: ``training/dataset/README.md`` §"Expected schema" requires all of these.
REQUIRED_COLUMNS = ("alerts", "platform", "description", "tools")


class RowSchemaError(ValueError):
    """A dataset row cannot say which environment produced it."""


def validate_corpus_schema(dataset: Any) -> None:
    """Refuse to start when a split cannot declare each row's environment.

    Args:
        dataset: anything mapping split names to objects with ``column_names`` (a
            ``datasets.DatasetDict``, or a plain dict in tests).

    Raises:
        RowSchemaError: a split is missing one of :data:`REQUIRED_COLUMNS`.
    """
    for split in dataset:
        columns = set(getattr(dataset[split], "column_names", ()) or ())
        missing = [name for name in REQUIRED_COLUMNS if name not in columns]
        if missing:
            raise RowSchemaError(
                f"dataset split {split!r} is missing {missing} (has: {sorted(columns)}); "
                "INTERFACES §8 and training/dataset/README.md require the environment "
                "columns because T_A is defined by the environment, not by a default "
                "(paper Eq.3)"
            )


def resolve_row_tools(example: Dict[str, Any]) -> List[str]:
    """The environment tool set declared by one dataset row.

    Raises:
        RowSchemaError: the row declares no tools, or names one that is not catalogued.
    """
    declared: Any = example.get("tools")
    if isinstance(declared, str):
        declared = [declared]
    if not declared:
        raise RowSchemaError(
            "the row declares no 'tools'; T_A must not fall back to the full catalogue "
            "(advertising a tool the environment never had)"
        )
    try:
        return list(catalogue_members(list(declared)))
    except ValueError as exc:
        raise RowSchemaError(str(exc)) from exc


def resolve_row_environment(example: Dict[str, Any]) -> tuple[List[str], str]:
    """``(tools, platform)`` for one row — the two facts the ``E`` section states.

    Raises:
        RowSchemaError: either fact is missing or unusable.
    """
    tools = resolve_row_tools(example)
    platform = str(example.get("platform") or "").strip()
    if not platform:
        raise RowSchemaError(
            "the row declares no 'platform'; the E section must state the environment it "
            "was produced in rather than defaulting to a guess"
        )
    return tools, platform
