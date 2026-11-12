# SPDX-License-Identifier: Apache-2.0
"""SOC transport used while computing the execution/evaluation reward stages.

``INTERFACES.md`` §3.1 defines one request per reward-evaluation round and §5 fixes
the ordering: deploy the **whole** strategy, then attack **once**.  This module
delegates to the single authoritative client in ``agent/tools/batch_executor.py``:

* **Dataset path** - one resolver instead of a ``Path(__file__).resolve().parents[n]``
  offset that can point at the wrong directory and silently fall back to hard-coded
  defaults.  There is exactly one resolver,
  :func:`resolve_dataset_path` (= ``agent.tools.batch_executor._dataset_path``),
  which raises ``DatasetPathError`` listing every location it searched.  It already
  includes ``training/dataset/security_dataset.json``, so the training loader in
  ``grpo.py`` and this transport agree on one corpus location by construction.
* **Per-tool fan-out** - :meth:`BatchExecutor.execute_strategy` submits the entire
  strategy in exactly one POST and returns the SOC's feedback vector, which is what
  ``sa_cascade_reward`` consumes.  One HTTP round trip per tool would evaluate a
  combined strategy as a sum of unrelated calls rather than as a unit.
"""

from __future__ import annotations

from open_r1._syspath import ensure_repo_root_on_path

ensure_repo_root_on_path()

from agent.tools.batch_executor import (  # noqa: E402  (import after sys.path shim)
    BatchExecutor,
    DatasetConfigError,
    DatasetPathError,
    SOCError,
    SOCUnavailableError,
    read_vm_config,
    resolve_dataset_path,
    soc_endpoint,
)

#: Convenience alias: the agent names the canonical resolver ``resolve_dataset_path``
#: (it is the public alias of the ``_dataset_path`` helper that ``INTERFACES.md`` §12
#: checks by name).
dataset_path = resolve_dataset_path

__all__ = [
    "BatchExecutor",
    "DatasetConfigError",
    "DatasetPathError",
    "SOCError",
    "SOCUnavailableError",
    "dataset_path",
    "read_vm_config",
    "resolve_dataset_path",
    "soc_endpoint",
]
