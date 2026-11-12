# SPDX-License-Identifier: Apache-2.0
"""Locate the SecLoop repository root and make the ``agent`` package importable.

SecLoop ships three subsystems that import from one another: ``target``/``ids``,
``battlefield``, ``agent`` and ``training``.  ``agent`` is a top-level package
rooted at the repository root, so when the training entry point is launched from
``training/`` (see ``train.sh``) the repository root has to be on ``sys.path``.

``INTERFACES.md`` §6/§7 require the training side to reuse the agent's tool
registry and LLM client instead of duplicating them; this module is the single
place that arranges the import path for those re-exports.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# <repo>/training/src/open_r1/_syspath.py -> parents[3] == <repo>
_DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[3]

_cached_repo_root: Optional[Path] = None


def _find_repo_root(start: Path) -> Path:
    """Return the first ancestor that holds both ``agent/`` and ``training/``."""
    for candidate in (start, *start.parents):
        if (candidate / "agent").is_dir() and (candidate / "training").is_dir():
            return candidate
    return _DEFAULT_REPO_ROOT


def repo_root() -> Path:
    """Absolute path of the SecLoop repository root."""
    global _cached_repo_root
    if _cached_repo_root is None:
        _cached_repo_root = _find_repo_root(Path(__file__).resolve().parent)
    return _cached_repo_root


def ensure_repo_root_on_path() -> Path:
    """Prepend the repository root to ``sys.path`` (idempotent)."""
    root = repo_root()
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return root


__all__ = ["ensure_repo_root_on_path", "repo_root"]
