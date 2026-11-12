# `training/` — SA-GRPO training subsystem

The reinforcement-learning side of SecLoop: it turns IDS
alerts into defensive strategies by optimising the paper's **SA-GRPO** objective
(IEEE JSAC vol. 44, 2026, DOI `10.1109/JSAC.2025.3643844`, Section III).

## What SA-GRPO actually is

SA-GRPO is GRPO with changed configuration values — the paper's contribution on the
optimisation side is a *configuration*, not new arithmetic, and this package says
so plainly instead of implying otherwise:

| change | paper | recipe key |
|---|---|---|
| advantage without division by the group standard deviation | Eq. 17, `A_i = r_i - mean({r})` | `scale_rewards: false` |
| KL divergence term removed | Section III-C | `beta: 0.0` |
| Clip-Higher: asymmetric clipping interval | Eq. 15, `clip(γ, 1-ε_low, 1+ε_high)` | `epsilon: 0.2`, `epsilon_high: 0.28` |
| loss normalised by `1/G` only, with no `1/|o_i|` per-sequence length factor | Eq. 14 | `loss_type: dr_grpo` |

`loss_type` is worth spelling out because Table IV does not list it and TRL's
default is not Eq. 14: `bnpo` normalises by the batch token count and `grpo` by each
sequence length, so only `dr_grpo` matches the equation's `1/G` denominator. The
recipe sets it explicitly, and `validate_sa_grpo_config()` checks it along with the
other values.

`SAGRPOTrainer` is therefore a thin validation/logging wrapper over
`trl.GRPOTrainer`; `validate_sa_grpo_config()` **refuses to start** a run whose
configuration does not implement those changes, so a reproduction attempt cannot
silently degrade into plain GRPO.

The part that *is* new code is the reward: `sa_cascade_reward` in
`src/open_r1/rewards.py`, the paper's Section III-B four-stage cascade.

## Reward cascade

```
R = R_format + R_exec + R_eva - P,   clipped to [0, 3]
```

| stage | paper | rule |
|---|---|---|
| `R_format` | Eq. 18 | JSON parses and every tool name is in the authoritative registry; failure scores exactly `0.0` |
| `R_exec` | Eq. 19 | `1.0` iff `rs_exe == 1.0`, else `0.0` |
| `R_eva` | Eq. 20 | `1 - rs_attack` (Eq. 20's "absence of alarms"); **not** gated on `rs_service` |
| `P` | Eq. 21 | LLM-judge over-defence level, subtracted |

**Polarity.** `rs_attack` reported by the policy execution validator is the raw
Eq. 11 measurement (high = the attack succeeded = the defence failed). It is never
inverted in the validator, and `1 - rs_attack` appears in exactly one place in the
whole project: stage 3 of `sa_cascade_reward`.

**Stage 3: blocking the attack earns the point, with no further condition.** That is the
paper's stated semantics for Eq. 20 ("1 indicates the absence of warning alarms"), evaluated
here as `1 - rs_attack`. `rs_service` is deliberately not a factor: reading §IV-D's
"effectively defends **and** does not cause any disruption" and §II-C-3's service-availability
signal into Eq. 20 would make the stage conditional on the service, which Eq. 20 itself does
not do. The cost is stated rather than hidden: a strategy that blocks the attack by breaking
the service also scores the point.
`rs_service` is still measured, still reported, and still enters `F_i` (Eq. 13) — but
`F_i` never enters the reward total (`R_format + R_exec + R_eva - P`), so **no term in the
reward counterbalances over-defence**; the Eq. 21 judge is the only reward-side check, and it
needs a configured endpoint.

A **missing** `rs_service` is different from a `0`: the feedback vector is then incomplete,
so the round is **unmeasured** and `R_exec = R_eva = 0.0` with a warning. Eq. 12 is never
inferred, and defaulting the missing field to `1` would hand full credit to a round whose
service was never probed.

**Retryable failures are excluded, not scored.** A VM pool at capacity answers `429`; that
is transport pressure, not a bad strategy (`INTERFACES.md` §3.1 requires the two to be
handled differently). The client honours `Retry-After` and retries with backoff, and a
retryable failure that survives the budget is **excluded from the sample** instead of being
turned into `R_exec = R_eva = 0.0`. Scoring it zero would teach the policy that a good
strategy failed.

**Parallel rounds.** A batch is scored on a `ThreadPoolExecutor`: each completion is one
SOC round, and `SECLOOP_REWARD_CONCURRENCY` (default `4`, capped at the number of
completions) sets how many are in flight. `executor.map` preserves order, so `rewards[i]`
still corresponds to `completions[i]`. Match it to the number of pairs in
`SOAR_VM_POOL`; beyond that, the extra threads just wait in the pool's `acquire()`.

**Failure policy.** The penalty stage is a real stage. When no LLM endpoint is
configured the judge raises (`PenaltyJudgeUnavailableError`) rather than quietly
returning `0.0`, so a mis-configured run cannot silently become an easier objective.

## Layout

```
training/
├── train.sh                                  launcher (accelerate + DeepSpeed ZeRO-2)
├── recipes/
│   ├── accelerate_configs/zero2.yaml
│   └── Qwen2.5-7B-Instruct/grpo/config.yaml  the paper's recipe (Table IV)
├── dataset/README.md                         how the IDS corpus is produced
├── tests/test_sa_cascade.py                  cascade contract tests
└── src/open_r1/
    ├── grpo.py                               entry point
    ├── configs.py                            dataclasses
    ├── rewards.py                            sa_cascade_reward + registry
    └── utils/
        ├── summarizer.py                     S_r adapter over ids/combine_ids_log.py
        ├── sa_grpo_trainer.py                SAGRPOTrainer + validation
        ├── llm_judge.py                      penalty judge (shared endpoint)
        ├── model_utils.py, wandb_logging.py
        └── security_tools.py, tool_manager.py, batch_executor.py   re-exports
```

The four `utils` re-export modules deliberately contain no canonical logic: the
tool registry, the `ToolManager`, the SOC transport and the `S_r` summarizer live
in `agent/tools/` and `ids/combine_ids_log.py` respectively and are the single
source of truth (`docs/INTERFACES.md` §6 and §9). `summarizer.py` adapts the
authority to the training prompt; the legacy pre-aggregated digest grammar is
available only through the explicitly named `parse_legacy_digest()`, which is
neither the default nor the dataset contract.

## Running it

```bash
cd training
pip install -r requirements.txt          # or: pip install -e .
# place or generate the IDS corpus: dataset/security_dataset.json (@see dataset/README.md)
# start the SOC server (battlefield/soc_server.py) and configure the shared LLM
# endpoint (docs/INTERFACES.md §7.1) - the penalty judge needs it
bash train.sh
```

`train.sh` passes everything through `${VAR:-default}` templates: `NUM_PROCESSES`
(7), `ACCELERATE_CONFIG`, `RECIPE`, `ACCELERATE_LOG_LEVEL`. It contains no
credentials and no endpoints.

### GPUs, and why training uses 7 of them

The paper's node has 8 A800s; Table IV uses group size `G = 7` with
`per_device_train_batch_size: 4` and `gradient_accumulation_steps: 1`. TRL requires
the effective batch (`4 × num_processes × 1`) to be divisible by `G`, which forces
`num_processes` to be a multiple of 7. The recipe's own numbers therefore imply
**7 training ranks plus one GPU for the generation server**, which is also what the
`zero2.yaml` accelerate config encodes.

For faster generation, start the optional server on the spare GPU and flip the flag:

```bash
trl vllm-serve --model Qwen/Qwen2.5-7B-Instruct --port 8000   # set use_vllm: true in the recipe
```

### Environment notes

* Python 3.11, `torch==2.6.0`, `transformers` and `trl` pinned to the upstream
  commits listed in `requirements.txt`.
* `attn_implementation: flash_attention_2` needs the optional `flash-attn` extra;
  use `sdpa` if the CUDA toolchain cannot build it.
* `trl` is a dependency, never vendored.

## Tests

```bash
cd training && python -m pytest tests -q
```

The cascade tests replace the SOC transport and the LLM judge through the
module-level seams of `open_r1.rewards`, so they run without a server or an
endpoint while still exercising the real validation, arithmetic and clipping.

## Licensing

Apache-2.0 (`LICENSE`). Parts derive from `huggingface/open-r1` (Apache-2.0).
