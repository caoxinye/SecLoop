# SPDX-License-Identifier: Apache-2.0
# Adapted from huggingface/open-r1 (Apache-2.0).
"""Configuration dataclasses for the SA-GRPO training entry point.

The config carries the fields the entry point reads: the SA-GRPO knobs inherited from
``trl.GRPOConfig``, the chat-template and system-prompt overrides, the logging-backend
metadata, and the corpus location.  It adds no benchmark or callback plumbing, and the
only reward setting is the registry key ``reward_funcs``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import trl

__all__ = ["GRPOConfig", "GRPOScriptArguments"]


@dataclass
class GRPOConfig(trl.GRPOConfig):
    """Training arguments shared with the prompt builder and the logging backend."""

    chat_template: Optional[str] = field(
        default=None,
        metadata={"help": "Chat template override; falls back to the tokenizer's template."},
    )
    system_prompt: Optional[str] = field(
        default=None,
        metadata={"help": "Optional system message placed before the user prompt."},
    )
    wandb_entity: Optional[str] = field(
        default=None,
        metadata={"help": "Weights & Biases entity for the run."},
    )
    wandb_project: Optional[str] = field(
        default=None,
        metadata={"help": "Weights & Biases project for the run."},
    )
    wandb_run_group: Optional[str] = field(
        default=None,
        metadata={"help": "Weights & Biases group for the run."},
    )
    allow_non_sa_grpo: bool = field(
        default=False,
        metadata={
            "help": (
                "Run even when the configuration does not implement SA-GRPO, for a deliberate "
                "GRPO baseline. Requirement violations are logged as errors instead of aborting "
                "the run. Default False, so a mis-configured run fails loudly."
            )
        },
    )


@dataclass
class GRPOScriptArguments(trl.ScriptArguments):
    """Script arguments: which reward to use and where the IDS corpus lives.

    Args:
        reward_funcs: registry keys resolved by ``open_r1.rewards.get_reward_funcs``.
            The SA-GRPO recipe uses exactly one entry: ``sa_cascade``.
        dataset_dir: directory holding ``security_dataset.json``.  Resolution order
            is ``dataset_dir`` -> ``SECLOOP_DATASET_DIR`` -> ``<training>/dataset``.
        dataset_name: when left at the local sentinel the corpus is read from
            ``dataset_dir``; any other value is passed to ``datasets.load_dataset``.
    """

    reward_funcs: list[str] = field(
        default_factory=lambda: ["sa_cascade"],
        metadata={"help": "Reward registry keys; the SA-GRPO recipe uses ['sa_cascade']."},
    )
    dataset_name: Optional[str] = field(
        default="local_security_dataset",
        metadata={"help": "Local sentinel, or a Hugging Face dataset identifier."},
    )
    dataset_dir: Optional[str] = field(
        default=None,
        metadata={"help": "Directory containing security_dataset.json (overrides SECLOOP_DATASET_DIR)."},
    )
