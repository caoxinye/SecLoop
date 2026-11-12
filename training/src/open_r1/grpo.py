# SPDX-License-Identifier: Apache-2.0
# Adapted from huggingface/open-r1 (Apache-2.0).
"""SA-GRPO training entry point for SecLoop.

Run it with ``bash train.sh`` (see ``README.md``); the recipe is
``recipes/Qwen2.5-7B-Instruct/grpo/config.yaml``.

What this script does
---------------------
1. loads the local IDS corpus (``security_dataset.json``) or a Hub dataset,
2. builds the prompt ``P = [C, T_A, E]`` with the agent's canonical prompt builder
   so the training and inference prompts are structurally identical
   (``INTERFACES.md`` §8): ``C`` from the summarizer, ``T_A`` from the authoritative
   tool registry, ``E`` from the dataset's environment columns,
3. refuses to start unless the configuration really implements SA-GRPO
   (``validate_sa_grpo_config``),
4. trains with :class:`SAGRPOTrainer` and ``reward_funcs: [sa_cascade]``.

The entry point depends on three shared pieces and nothing else: the prompt builder,
the tool registry and the summarizer.  There is no separate orchestrator module, and
the recipe has no flag that would enable one.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import datasets
import torch
import transformers
from transformers import set_seed
from transformers.trainer_utils import get_last_checkpoint

from open_r1._syspath import ensure_repo_root_on_path
from open_r1.configs import GRPOConfig, GRPOScriptArguments
from open_r1.rewards import get_reward_funcs
from open_r1.utils import get_tokenizer
from open_r1.utils.sa_grpo_trainer import SAGRPOTrainer, validate_sa_grpo_config
from open_r1.utils.summarizer import Summarizer
from open_r1.utils.wandb_logging import init_wandb_training
from trl import ModelConfig, TrlParser, get_peft_config

# The shared agent abstractions are imported after the shim so that `agent` resolves
# from the repository root regardless of the current working directory.
ensure_repo_root_on_path()

from agent.llm.llm_interface import build_messages  # noqa: E402  (import after sys.path shim)
from agent.tools.batch_executor import read_vm_config  # noqa: E402
from open_r1.utils.prompt_rows import (  # noqa: E402  (import after sys.path shim)
    RowSchemaError,
    resolve_row_environment,
    validate_corpus_schema,
)
from open_r1.utils.security_tools import create_security_tools  # noqa: E402  (import after sys.path shim)

logger = logging.getLogger(__name__)

#: Value of ``dataset_name`` that selects the repository-local IDS corpus.
LOCAL_DATASET_SENTINEL = "local_security_dataset"

#: File name produced by the IDS pipeline (``INTERFACES.md`` §9/§11).
DATASET_FILENAME = "security_dataset.json"
DATASET_TEST_FILENAME = "security_dataset_test.json"


def _candidate_dataset_dirs(script_args: GRPOScriptArguments) -> List[Path]:
    """Directories searched for the local corpus, most specific first."""
    candidates: List[Path] = []
    if getattr(script_args, "dataset_dir", None):
        candidates.append(Path(str(script_args.dataset_dir)).expanduser())
    env_dir = os.environ.get("SECLOOP_DATASET_DIR")
    if env_dir:
        candidates.append(Path(env_dir).expanduser())
    candidates.append(Path(__file__).resolve().parents[2] / "dataset")  # <training>/dataset
    return candidates


def load_training_dataset(script_args: GRPOScriptArguments) -> datasets.DatasetDict:
    """Load the IDS corpus: either the local JSON file or a Hub dataset.

    Raises:
        FileNotFoundError: the local corpus is selected but cannot be found.  The
            message lists every directory that was searched and points at the IDS
            pipeline that produces the file, so a missing corpus is never a silent
            empty training set.
    """
    if script_args.dataset_name and script_args.dataset_name != LOCAL_DATASET_SENTINEL:
        logger.info("loading dataset %s from the Hub", script_args.dataset_name)
        return datasets.load_dataset(script_args.dataset_name, name=script_args.dataset_config)

    searched = _candidate_dataset_dirs(script_args)
    train_file = next((directory / DATASET_FILENAME for directory in searched if (directory / DATASET_FILENAME).is_file()), None)
    if train_file is None:
        raise FileNotFoundError(
            "the local IDS corpus was not found. Looked for "
            f"{DATASET_FILENAME} in: {[str(directory) for directory in searched]}. "
            "Generate it with the IDS pipeline (`ids/combine_ids_log.py`, INTERFACES.md §9), copy an "
            "existing corpus into `<training>/dataset/`, or point `dataset_dir` / SECLOOP_DATASET_DIR at it."
        )

    test_file = train_file.with_name(DATASET_TEST_FILENAME)
    if test_file.is_file():
        data_files = {"train": str(train_file), "test": str(test_file)}
    else:
        logger.warning(
            "%s is absent; the train split is reused as the test split, so any evaluation number is "
            "contaminated. Enable evaluation only after a held-out corpus exists.",
            DATASET_TEST_FILENAME,
        )
        data_files = {"train": str(train_file), "test": str(train_file)}

    logger.info("loading local IDS corpus from %s", train_file)
    return datasets.load_dataset("json", data_files=data_files)


def build_prompt_messages(
    example: Dict[str, Any],
    tool_manager: Any,
    summarizer: Summarizer,
    system_prompt: Optional[str],
) -> List[Dict[str, str]]:
    """Assemble the ``P = [C, T_A, E]`` conversation for one dataset row.

    ``build_messages`` is the agent's canonical builder, so the training and
    inference prompts cannot drift apart (``INTERFACES.md`` §8).

    Returns an empty list when the row cannot produce a valid prompt.  The caller
    filters those rows out: ``build_messages`` deliberately raises on an empty ``C``
    (that guard is the contract guarantee), and letting the exception escape inside
    ``dataset.map`` would abort the whole run with an unrelated traceback.
    """
    raw_alerts = example.get("alerts") or ""
    ids_summary = summarizer.summarize_to_str(raw_alerts)
    if not ids_summary:
        logger.error(
            "dropping dataset row: no usable alert summary, and INTERFACES §8 requires a non-empty C "
            "section (raw alerts were %s characters)",
            len(raw_alerts),
        )
        return []

    # The row's environment decides T_A (paper Eq.3) -- never the catalogue, and never a
    # hard-coded default. `tool_manager` is used only to render the same §6 text.
    try:
        environment_tools, platform = resolve_row_environment(example)
    except RowSchemaError as exc:
        logger.error("dropping dataset row: %s", exc)
        return []

    tool_descriptions = tool_manager.get_tool_descriptions(environment_tools)
    description = example.get("description") or ""

    try:
        return build_messages(
            ids_summary,
            tool_descriptions,
            system_prompt=system_prompt,
            platform=platform,
            description=description,
            available_tools=list(environment_tools),
        )
    except ValueError as exc:
        raise ValueError(f"cannot build P = [C, T_A, E] for this dataset row: {exc}") from exc


def main(script_args: GRPOScriptArguments, training_args: GRPOConfig, model_args: ModelConfig) -> None:
    """Run SA-GRPO training end to end."""
    set_seed(training_args.seed)

    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    log_level = training_args.get_process_log_level()
    logger.setLevel(log_level)
    datasets.utils.logging.set_verbosity(log_level)
    transformers.utils.logging.set_verbosity(log_level)
    transformers.utils.logging.enable_default_handler()
    transformers.utils.logging.enable_explicit_format()

    logger.info(
        "process rank %s, device %s, n_gpu %s, distributed %s",
        training_args.local_rank,
        training_args.device,
        training_args.n_gpu,
        bool(training_args.local_rank != -1),
    )
    logger.info("model arguments: %s", model_args)
    logger.info("script arguments: %s", script_args)
    logger.info("training arguments: %s", training_args)

    last_checkpoint = None
    if os.path.isdir(training_args.output_dir):
        last_checkpoint = get_last_checkpoint(training_args.output_dir)
    if last_checkpoint is not None and training_args.resume_from_checkpoint is None:
        logger.info("checkpoint detected, resuming from %s", last_checkpoint)

    if "wandb" in training_args.report_to:
        init_wandb_training(training_args)

    dataset = load_training_dataset(script_args)
    # Refuse to start unless the corpus can say which environment produced each row: T_A
    # is defined by the environment (paper Eq.3), and during training the corpus is the
    # only record of it.
    validate_corpus_schema(dataset)
    # ...and resolve the VM pair *now*, not on the first reward call. `read_vm_config()`
    # raises DatasetConfigError when the corpus is missing `attack_mode`/`red_vm_name`/
    # `blue_vm_name` and no SOAR_* variable pins them. Left to the reward path, that
    # exception is swallowed into "unmeasured" for every sample, which silently reduces
    # training to the format reward alone -- the exact ablation the paper reports as
    # costing accuracy -- with only warnings to show for it.
    read_vm_config()

    tokenizer = get_tokenizer(model_args, training_args)
    reward_funcs = get_reward_funcs(script_args)

    tool_manager = create_security_tools()
    summarizer = Summarizer()

    def make_conversation(example: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "prompt": build_prompt_messages(
                example,
                tool_manager,
                summarizer,
                getattr(training_args, "system_prompt", None),
            )
        }

    dataset = dataset.map(make_conversation)

    for split in list(dataset):
        total = len(dataset[split])
        dataset[split] = dataset[split].filter(lambda row: len(row["prompt"]) > 0)
        dropped = total - len(dataset[split])
        if dropped:
            logger.warning(
                "dropped %d of %d rows from the %s split: they could not produce a P = [C, T_A, E] prompt",
                dropped,
                total,
                split,
            )
        if len(dataset[split]) == 0:
            raise ValueError(
                f"the {split} split is empty after filtering rows without a usable alert summary; "
                "check that the IDS pipeline wrote real Suricata alerts into the dataset"
            )

    for split in dataset:
        if "messages" in dataset[split].column_names:
            dataset[split] = dataset[split].remove_columns("messages")

    logger.info("initialising model kwargs")
    torch_dtype = (
        model_args.torch_dtype
        if model_args.torch_dtype in ["auto", None]
        else getattr(torch, str(model_args.torch_dtype))
    )
    training_args.model_init_kwargs = dict(
        revision=model_args.model_revision,
        trust_remote_code=bool(getattr(model_args, "trust_remote_code", False)),
        attn_implementation=model_args.attn_implementation,
        torch_dtype=torch_dtype,
        use_cache=not bool(getattr(training_args, "gradient_checkpointing", False)),
    )

    # Refuse to train something that is not SA-GRPO (INTERFACES.md §10.1), unless the
    # operator explicitly asked for a baseline: `allow_non_sa_grpo` is how the CLI reaches
    # the "deliberate GRPO baseline" escape hatch that `validate_sa_grpo_config` documents.
    validate_sa_grpo_config(
        training_args,
        strict=not bool(getattr(training_args, "allow_non_sa_grpo", False)),
    )

    trainer = SAGRPOTrainer(
        model=model_args.model_name_or_path,
        reward_funcs=reward_funcs,
        args=training_args,
        train_dataset=dataset[script_args.dataset_train_split],
        eval_dataset=(
            dataset[script_args.dataset_test_split] if training_args.eval_strategy != "no" else None
        ),
        peft_config=get_peft_config(model_args),
        processing_class=tokenizer,
    )

    logger.info("training")
    checkpoint = None
    if training_args.resume_from_checkpoint is not None:
        checkpoint = training_args.resume_from_checkpoint
    elif last_checkpoint is not None:
        checkpoint = last_checkpoint
    train_result = trainer.train(resume_from_checkpoint=checkpoint)
    metrics = train_result.metrics
    metrics["train_samples"] = len(dataset[script_args.dataset_train_split])
    trainer.log_metrics("train", metrics)
    trainer.save_metrics("train", metrics)
    trainer.save_state()

    logger.info("saving model")
    trainer.save_model(training_args.output_dir)
    logger.info("model saved to %s", training_args.output_dir)

    model_card_kwargs = {"dataset_name": script_args.dataset_name, "tags": ["secloop", "sa-grpo"]}
    if trainer.accelerator.is_main_process:
        trainer.create_model_card(**model_card_kwargs)
        trainer.model.config.use_cache = True
        trainer.model.config.save_pretrained(training_args.output_dir)

    if training_args.do_eval:
        logger.info("evaluating")
        eval_metrics = trainer.evaluate()
        eval_metrics["eval_samples"] = len(dataset[script_args.dataset_test_split])
        trainer.log_metrics("eval", eval_metrics)
        trainer.save_metrics("eval", eval_metrics)

    if training_args.push_to_hub:
        logger.info("pushing to the Hub")
        trainer.push_to_hub(**model_card_kwargs)


if __name__ == "__main__":
    parser = TrlParser((GRPOScriptArguments, GRPOConfig, ModelConfig))
    parsed_script_args, parsed_training_args, parsed_model_args = parser.parse_args_and_config()
    main(parsed_script_args, parsed_training_args, parsed_model_args)
