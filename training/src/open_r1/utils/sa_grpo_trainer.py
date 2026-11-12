# SPDX-License-Identifier: Apache-2.0
"""SA-GRPO trainer wrapper and configuration validation (paper Section III-A).

Honest scope statement
----------------------
SA-GRPO's algorithmic changes relative to GRPO are **configuration values**, not
new arithmetic: upstream ``trl.GRPOTrainer`` already implements the advantage
estimator (Eq. 17), the asymmetric clip (Eq. 15), the optional KL term and the
loss normalisation.  What makes a run "SA-GRPO" is that the recipe sets:

* ``scale_rewards: false``  -> ``A_i = r_i - mean(r)``, no division by the group std
* ``beta: 0.0``             -> the KL divergence term is excluded
* ``epsilon: 0.2`` with ``epsilon_high: 0.28`` -> asymmetric Clip-Higher
* ``loss_type: dr_grpo``    -> Eq. 14 normalises by ``1/G`` only, with no
  ``1/|o_i|`` per-sequence length factor; ``dr_grpo`` is the only TRL value with
  that property (``bnpo`` normalises by the batch token count, ``grpo`` by each
  sequence length).  Table IV omits this row, but Eq. 14 and the run this recipe
  reproduces both require it.

So :class:`SAGRPOTrainer` is a *validation and logging* wrapper.  It adds no maths
and it does not pretend to; anyone reading it should be able to confirm that the
paper's objective is entirely the upstream implementation under a specific
configuration.
"""

from __future__ import annotations

import logging
from typing import Any, List

from trl import GRPOTrainer

logger = logging.getLogger(__name__)

__all__ = ["SAGRPOMisconfigurationError", "SAGRPOTrainer", "validate_sa_grpo_config"]


class SAGRPOMisconfigurationError(ValueError):
    """The training arguments do not implement the paper's SA-GRPO objective."""


class SAGRPOTrainer(GRPOTrainer):
    """``trl.GRPOTrainer`` with SA-GRPO configuration logging and validation.

    Example:
        trainer = SAGRPOTrainer(
            model=model_args.model_name_or_path,
            reward_funcs=[sa_cascade_reward],
            args=training_args,          # GRPOConfig with the SA-GRPO values
            train_dataset=dataset["train"],
            processing_class=tokenizer,
        )
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._log_sa_grpo_config()

    def _log_sa_grpo_config(self) -> None:
        """Log the effective objective configuration (defence against silent drift)."""
        args = self.args
        epsilon_low = getattr(args, "epsilon", None)
        epsilon_high = getattr(args, "epsilon_high", None) or epsilon_low
        scale_rewards = getattr(args, "scale_rewards", None)
        beta = getattr(args, "beta", None)
        loss_type = getattr(args, "loss_type", None)

        logger.info("=== SA-GRPO configuration ===")
        logger.info(
            "  advantage: A_i = r_i - mean({r_i})%s (scale_rewards=%s)",
            "" if not scale_rewards else " / std({r_i})",
            scale_rewards,
        )
        logger.info("  KL term: %s (beta=%s)", "EXCLUDED" if beta == 0.0 else "ACTIVE", beta)
        logger.info(
            "  clipping: ratio in [%s, %s] (epsilon=%s, epsilon_high=%s)",
            1 - epsilon_low if epsilon_low is not None else None,
            1 + epsilon_high if epsilon_high is not None else None,
            epsilon_low,
            epsilon_high,
        )
        logger.info(
            "  loss_type: %s (Table IV does not list it; the recipe pins 'dr_grpo' to match "
            "Eq. 14, and this function enforces that)",
            loss_type,
        )
        logger.info("==============================")


def validate_sa_grpo_config(training_args: Any, strict: bool = True) -> List[str]:
    """Check that ``training_args`` implements SA-GRPO (``INTERFACES.md`` §10.1).

    Args:
        training_args: the parsed ``GRPOConfig``.
        strict: when ``True`` (default) raise on the first violated requirement so
            a mis-configured run cannot start and silently train plain GRPO.  When
            ``False``, return the list of problems instead - useful when a
            deliberate GRPO baseline is being run.

    Returns:
        The list of requirement violations (always empty when ``strict`` is ``True``).

    Raises:
        SAGRPOMisconfigurationError: ``strict`` is ``True`` and a requirement fails.
    """
    issues: List[str] = []

    if getattr(training_args, "scale_rewards", None):
        issues.append(
            "scale_rewards=True divides the advantage by the group standard deviation; "
            "SA-GRPO requires scale_rewards=False"
        )

    if getattr(training_args, "beta", None) != 0.0:
        issues.append(
            f"beta={getattr(training_args, 'beta', None)} keeps the KL divergence term; SA-GRPO requires beta=0.0"
        )

    epsilon_low = getattr(training_args, "epsilon", None)
    epsilon_high = getattr(training_args, "epsilon_high", None)
    if epsilon_high is None:
        issues.append(
            "epsilon_high is unset, so clipping is symmetric and Clip-Higher is disabled; "
            "SA-GRPO requires epsilon_high > epsilon (paper: 0.28 > 0.2)"
        )
    elif epsilon_low is None or float(epsilon_high) <= float(epsilon_low):
        issues.append(
            f"epsilon_high={epsilon_high} <= epsilon={epsilon_low}; Clip-Higher requires epsilon_high > epsilon"
        )

    num_generations = getattr(training_args, "num_generations", None)
    if num_generations != 7:
        issues.append(f"num_generations={num_generations}; the paper's group size is G=7 (Table IV)")

    loss_type = getattr(training_args, "loss_type", None)
    if loss_type != "dr_grpo":
        issues.append(
            f"loss_type={loss_type!r} does not match Eq. 14, which normalises by 1/G only "
            "(no 1/|o_i| per-sequence length factor); SA-GRPO requires loss_type='dr_grpo' "
            "('bnpo' normalises by the batch token count, 'grpo' by each sequence length)"
        )

    if issues:
        for issue in issues:
            logger.error("SA-GRPO configuration mismatch: %s", issue)
        if strict:
            raise SAGRPOMisconfigurationError(
                "the training configuration does not implement SA-GRPO: "
                + "; ".join(issues)
                + ". Fix recipes/Qwen2.5-7B-Instruct/grpo/config.yaml (INTERFACES.md §10.1) "
                "or pass --allow_non_sa_grpo (equivalently "
                "validate_sa_grpo_config(strict=False)) to run a deliberate GRPO baseline."
            )
        return issues

    logger.info(
        "SA-GRPO configuration validated: scale_rewards=False, beta=0.0, epsilon=%.3f < "
        "epsilon_high=%.3f, G=%s, loss_type=%s",
        float(epsilon_low),
        float(epsilon_high),
        num_generations,
        loss_type,
    )
    return []
