#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Launch SA-GRPO training (DeepSpeed ZeRO-2 + bf16) on a single node of 8 GPUs.
#
# Every value below is a `${VAR:-default}` template: the script contains no
# credentials, no endpoints and no machine-specific paths.  Set the variables in
# your environment to override them.
#
#   8-GPU node layout: 7 training ranks + 1 GPU for the vLLM generation server.
#   Training uses 7 ranks because TRL requires the effective batch
#   (per_device_train_batch_size x num_processes x gradient_accumulation_steps
#   = 4 x 7 x 1 = 28) to be divisible by num_generations = 7.
#
#   To train with vLLM generation, on the spare GPU run
#       trl vllm-serve --model Qwen/Qwen2.5-7B-Instruct --port 8000
#   then set `use_vllm: true` in the recipe (see README.md).
#
#   The penalty judge of the reward cascade reads its endpoint from the shared
#   agent configuration (INTERFACES.md §7.1), not from this script.

set -euo pipefail

cd "$(dirname "$0")"

NUM_PROCESSES="${NUM_PROCESSES:-7}"
ACCELERATE_CONFIG="${ACCELERATE_CONFIG:-recipes/accelerate_configs/zero2.yaml}"
RECIPE="${RECIPE:-recipes/Qwen2.5-7B-Instruct/grpo/config.yaml}"
LOG_LEVEL="${ACCELERATE_LOG_LEVEL:-info}"

# `open_r1` lives under src/ and `agent` at the repository root; both must be
# importable even when the package has not been pip-installed.
export PYTHONPATH="$(pwd)/src${PYTHONPATH:+:$PYTHONPATH}"

ACCELERATE_LOG_LEVEL="${LOG_LEVEL}" accelerate launch \
    --config_file "${ACCELERATE_CONFIG}" \
    --num_processes "${NUM_PROCESSES}" \
    src/open_r1/grpo.py \
    --config "${RECIPE}" \
    "$@"
