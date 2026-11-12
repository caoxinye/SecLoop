# `agent/` — SecLoop blue-team agent (paper §II-B)

Closed loop: **real Suricata alert → `P = [C, T_A, E]` → LLM strategy → one SOC round →
feedback vector**. Every file starts with `# SPDX-License-Identifier: Apache-2.0`.

```
agent/
├── main.py                  CLI (closed loop, --dry-run, --print-prompt, self-checks)
├── config.json              INTERFACES §7.1 endpoint config — zero keys, zero vendor names
├── requirements.txt         pinned runtime deps (requests only, by design)
├── llm/
│   └── llm_interface.py     vendor-neutral LLM client + P=[C,T_A,E] builder  ← shared with training
└── tools/
    ├── security_tools.py    3-tool catalogue — CROSS-SUBSYSTEM SINGLE SOURCE OF TRUTH (§6)
    ├── tool_manager.py      registry, T_A rendering, strategy validation
    └── batch_executor.py    SOC transport: ONE request per strategy (§3/§5)
```

## Wiring points for the training path (`training/**`)

Export | What it is | Who uses it
---|---|---
`agent.llm.llm_interface.get_llm_client` | **the** endpoint factory (shared by the agent, `use_vllm` generation and the cascade reward's penalty judge) | `training/src/open_r1/rewards.py`
`agent.llm.llm_interface.LLMClient` | the client class (`chat`, `complete`, `check`, `generate_tool_calls`) | same
`agent.llm.llm_interface.build_prompt` / `build_messages` | canonical `P = [C, T_A, E]` in the frozen order **C → T_A → E** | `training/src/open_r1/grpo.py`
`agent.tools.security_tools.create_security_tools()` | `ToolManager` over the tools the SOC **probed** (`available=`); with no probe it registers the whole catalogue for membership checks and warns | `training/src/open_r1/utils/security_tools.py` (re-export, do not copy)
`agent.tools.security_tools.TOOL_SPECS` / `TOOL_NAMES` | the **full** catalogue re-exported in §6 order; the table itself is `battlefield/soc/tool_catalogue.py` | same
`agent.tools.security_tools.get_tool_descriptions(available)` | the `T_A` text for the probed tool set (`powershell` is absent when the target cannot run it) | prompt assembly
`agent.tools.batch_executor.BatchExecutor.capabilities()` | `GET /capabilities` — the probe that decides `T_A` (paper Eq. 3); raises rather than guessing | prompt assembly
`agent.tools.batch_executor.BatchExecutor` | one-request-per-strategy SOC client (`submit_strategy`, `execute_strategy`, `compute_rs_exe`) | reward execution stage

`agent` is a package rooted at the **SecLoop repository root**, so code in `training/` needs
that root on `sys.path`:

```python
import sys; from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))   # .../SecLoop
from agent.llm.llm_interface import get_llm_client, LLMConfigError
```

```python
judge = get_llm_client()                       # agent/config.json, INTERFACES §7.1
verdict = judge.chat([{"role": "user", "content": penalty_prompt}], temperature=0.0)
```

`get_llm_client()` **raises `LLMConfigError`** when no endpoint is configured and
`LLMEndpointError` when it is unreachable — it never returns `0.0`/`""`. In the cascade
reward, let that propagate (or map it to an explicit reward error); do not swallow it.

Because the prompt builder is shared, the inference prompt and the training prompt are
identical by construction: both prompt paths call the same helper in `grpo.py`.

## Configuration (`agent/config.json`, INTERFACES §7.1)

```json
{"llm": {"base_url": "http://127.0.0.1:8000/v1",
         "model": "secloop-qwen2.5-7b-instruct",
         "api_key_env": "LLM_API_KEY",     // an env-var NAME — never a value
         "temperature": 0.0,
         "timeout_s": 120}}
```

* Only the OpenAI-compatible serving protocol is used, addressed by `base_url`; that is how
  a locally served model (vLLM / SGLang / Ollama / TGI) is reached. No cloud endpoint, no
  vendor SDK, no key in the tree.
* `api_key_env` names an environment variable. When it is unset, no `Authorization` header
  is sent (local servers need none).
* `SECLOOP_AGENT_CONFIG` overrides the config path; `SOAR_ABILITY_ENDPOINT` overrides the
  SOC endpoint (`http://127.0.0.1:8988/execute_ability`, INTERFACES §1).
* The non-`llm` blocks (`environment`, `agent`) are agent-local: `environment` supplies the
  `E` section at inference time (the training path takes `E` from the dataset record).

## CLI

```bash
python -m agent.main --ids-summary-file /var/log/suricata/fast.log     # full closed loop
python -m agent.main --ids-summary-file fast.log --dry-run            # strategy only
python -m agent.main --ids-summary-file fast.log --print-prompt       # show P = [C, T_A, E]
python -m agent.main --check-llm                                      # endpoint self-check
python -m agent.main --check-soc                                      # SOC GET /health
python -m agent.llm.llm_interface --check                             # §7.2 self-check
```

Exit codes: `0` ok · `2` usage/input (missing or empty alert file) · `3` configuration ·
`4` LLM endpoint · `5` strategy (unparseable / contract violation) · `6` SOC.

`C` comes from the shared summariser `S_r` in `ids/combine_ids_log.py` (INTERFACES §9). If
that module is not importable, the CLI fails with an explanation; `--allow-raw-alerts`
accepts the raw Suricata lines verbatim instead and the result names that origin. It never
fabricates alerts, and an empty `C` always aborts the run.

## Execution model

One round = **one** `POST /execute_ability` carrying the canonical `{"strategy": [...]}`
body (INTERFACES §3.1). The SOC deploys the whole strategy, runs the attack once and returns
the 3-D feedback vector; `BatchExecutor` relays `rs_exe` / `rs_attack` / `rs_service` /
`F_i` verbatim and never recomputes or defaults them. A strategy is deployed in one
round trip rather than one per tool. VM-name resolution is explicit and logged
(`read_vm_config` in `agent/tools/batch_executor.py`): an operator pin
(`SOAR_RED_VM` / `SOAR_BLUE_VM` / `SOAR_ATTACK_MODE`) wins; otherwise the dataset
record; and if no dataset can be found at all it uses the INTERFACES §1 constants
**with a warning naming the missing dataset**. That last step is a fallback, and it is
loud: a VM name is never substituted silently, so a typo in a path cannot look like a
healthy run.
