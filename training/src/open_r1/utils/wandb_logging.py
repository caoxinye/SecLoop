# SPDX-License-Identifier: Apache-2.0
"""Weights & Biases environment wiring for the training entry point.

Only the *names* of the environment variables are set here; every credential stays
in the operator's environment.  The repository contains no keys (``INTERFACES.md``
§7.1).
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["init_wandb_training"]


def init_wandb_training(training_args: Any) -> None:
    """Forward the configured run metadata to the logging backend's environment."""
    entity = getattr(training_args, "wandb_entity", None)
    project = getattr(training_args, "wandb_project", None)
    run_group = getattr(training_args, "wandb_run_group", None)

    if entity is not None:
        os.environ["WANDB_ENTITY"] = str(entity)
    if project is not None:
        os.environ["WANDB_PROJECT"] = str(project)
    if run_group is not None:
        os.environ["WANDB_RUN_GROUP"] = str(run_group)

    logger.debug(
        "logging backend environment: entity=%s project=%s run_group=%s",
        entity,
        project,
        run_group,
    )
