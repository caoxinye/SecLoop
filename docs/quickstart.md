# Quickstart

This walks through bringing up the isolated lab and running one complete
SecLoop cycle. It assumes VMware Workstation Pro, Vagrant and the
`vagrant-vmware-desktop` plugin are installed (see the main
[README](../README.md) for versions).

> **Read [SECURITY.md](../SECURITY.md) first.** The lab is deliberately
> vulnerable and must stay on a host-only network.

## 1. Bring up the lab

```sh
cd vagrant
vagrant up
```

First run downloads two base boxes (`kalilinux/rolling`, `bento/ubuntu-18.04`)
and provisions both machines. The target provisioner installs Apache, PHP,
MySQL, the reference web application and Suricata, then validates the ruleset.

**Then create the snapshots the SOC restores between rounds.** A VMware snapshot
is a *host* operation, so no guest provisioner can create one:

```sh
bash snapshots.sh          # kali + target -> kali_init / target_init
```

`bash up.sh` does `vagrant up` followed by `snapshots.sh` in one step. Skipping
this step is not a fast failure: the round gets as far as the snapshot step and
then reports `snapshot restore failed` with `feedback: null`. See `snapshots.md`.

Check that the target is alive:

```sh
curl -s http://192.168.57.200/index.php
# SecLoop target OK
```

Check that Suricata is running and has the local rules loaded:

```sh
vagrant ssh target -c 'sudo suricatasc -c ruleset-stats | head'
```

## 2. Install SOC dependencies

```sh
pip install -r requirements/battlefield.txt
```

## 3. Start the SOC server

```sh
python battlefield/soc_server.py
# * Running on http://127.0.0.1:8988
```

The bind address defaults to loopback. Set `SOAR_SOC_HOST` / `SOAR_SOC_PORT` to
change it; binding to a non-loopback address exposes a remote-command service and
is logged as a warning when you do.

Verify it is healthy:

```sh
curl -s http://127.0.0.1:8988/health
# {"status": "ok", "attack_modes": ["sqli"], "vm_pool_size": 1, "available_pairs": 1,
#  "vagrant_root": "...", "api_version": "1.0", "pre_attack_sample": false,
#  "require_snapshot": true}   <- the last five are diagnostic; clients ignore unknown keys
#  `pre_attack_sample` is the shipped default (PipelineConfig); enabling it costs one extra
#  attack per round.
```

## 4. Serve the strategy model (optional for a first smoke test)

The loop needs a model to generate strategies. Any **OpenAI-compatible** server works
(`docs/INTERFACES.md` §7); the agent only needs `base_url` and `model` in
`agent/config.json`.

### Verified recipe: llama.cpp, no GPU required

The paper serves **Qwen2.5-7B-Instruct** (vLLM, on A800s). To exercise the pipeline on a
plain desktop, a small GGUF in the same model family is enough — this is the exact
combination the loop was validated with:

```sh
# 1. llama.cpp runtime (CPU build; grab the current tag from the releases page)
curl -L -o llama-cpu.zip \
  https://github.com/ggml-org/llama.cpp/releases/download/b11429/llama-b11429-bin-win-cpu-x64.zip
# The build tag is pinned deliberately: the lab was verified against b11429, and a
# newer release can rename flags. Substitute a newer tag only if you re-check the
# `llama-server` invocation below against that release's `--help`.

# 2. the model.  If huggingface.co is unreachable, hf-mirror.com serves the same repo
curl -L -o qwen2.5-0.5b-instruct-q4_k_m.gguf \
  https://hf-mirror.com/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf

# 3. serve it (469 MB, runs on CPU)
llama-server -m qwen2.5-0.5b-instruct-q4_k_m.gguf \
  --host 127.0.0.1 --port 8000 -c 4096 -t 8 --jinja
```

`--jinja` is required: it applies the chat template embedded in the GGUF. llama.cpp
accepts any `model` string, so the shipped `agent/config.json` works unmodified (the
`--check` below only *warns* that the configured name is not in `/v1/models`).

Then verify connectivity:

```sh
python -m agent.main --check-soc    # SOC reachable
python -m agent.llm.llm_interface --check
# LLM endpoint OK: http://127.0.0.1:8000/v1 model=<served-model-name>
```

A round is not one attack: the SOC waits for a free VM pair, deploys the strategy, runs
a whole attack (`SOC_ATTACK_TIMEOUT_S`, default 900 s), and rolls the blue VM back
(whose `snapshot_list` and `snapshot_restore` are each bounded by a separate 900 s
watchdog). The agent's read timeout is therefore derived from the SOC's own phase
budgets — currently **3600 s** — and is overridable:

```sh
SOAR_ROUND_TIMEOUT_S=5400 python agent/main.py --ids-summary-file /tmp/fast.log
```

`tests/test_agent_soc_round_timeout.py` re-reads those SOC budgets from source and
fails if this default ever stops covering them.

> **One platform per prompt.** The prompt path must not be self-contradictory: a config that
> lists `powershell` under `environment.tools` while `platform` is `Linux` renders
> `P = [C, T_A, E]` saying `Platform: Linux` and then offers a tool labelled *"Windows
> targets only"*. The model picks `powershell`, and the SOC runs it through `bash -lc`
> (its template is `{command}`, identical to `bash`), so `rs_exe` credits a tool that never
> executed.
>
> `T_A` is **measured, not assumed**. There is one table
> (`battlefield/soc/tool_catalogue.py`) recording what each tool *needs* — a workstation
> may lack `iptables`, or `sudo` may not work — and `GET /capabilities` asks the blue-team
> VM what it actually has:
>
> ```sh
> python agent/main.py --check-soc            # is the SOC up?
> curl -s http://127.0.0.1:8988/capabilities  # what can this VM actually run?
> ```
>
> On the shipped lab that answers `os=Linux, root_available=true,
> binaries=[bash, iptables, sh]` → `available_tools=[block_ip, bash]`, each refusal
> explained. If the SOC cannot probe the VM it returns **HTTP 503** rather than a
> plausible-looking list. The 19 s probe is cached per VM.
>
> Because `T_A` is a measurement, `--print-prompt` needs the SOC running. To inspect the
> prompt offline, **declare** the tools instead — the result is labelled
> `tool_source="declared"` and warned about, because a declaration is not a probe:
>
> ```sh
> python agent/main.py --print-prompt --tools block_ip,bash --ids-summary-file <fast.log>
> ```
>
> Separately, the model quality is also limited: a 0.5B model gets the JSON **format**
> right but not the **judgement**. That is enough to prove the pipeline end to end, not
> enough to match the paper's decision quality (Qwen2.5-**7B**-Instruct) — use a
> 7B-class model for that.

Without a served model, the SOC and the lab can still be exercised directly — see step 6.

## 5. Run one loop

Generate an alert by running the probe once so Suricata sees it, then hand the
resulting log to the agent:

```sh
vagrant ssh kali -c 'cd ~/attacks && python3 sqli_lab.py --target-ip 192.168.57.200'
vagrant ssh target -c 'sudo tail -n 50 /var/log/suricata/fast.log' > /tmp/fast.log

python agent/main.py --ids-summary-file /tmp/fast.log
```

`agent/main.py` summarises the alerts into `C`, builds the prompt
`P = [C, T_A, E]`, asks the model for a JSON strategy, submits the **whole
strategy in one request** to the SOC, and prints the feedback vector.

Expected shape of the output:

```
alert summary        : <compressed alert text>
strategy             : [{"tool": "block_ip", "params": {"ip": "192.168.57.199"}}]
feedback.rs_exe      : 1.0
feedback.rs_attack   : 0.0
feedback.rs_service  : 1
feedback.F_i         : 2.0
defense_effectiveness: 1.0
```

A working defence drives `rs_attack` towards `0.0` while `rs_service` stays at
`1`. If the strategy does nothing, `rs_attack` stays near `1.0`.

## 6. Exercise the SOC without a model

Useful for checking the lab and the validator in isolation:

```sh
curl -s -X POST http://127.0.0.1:8988/execute_ability \
  -H 'Content-Type: application/json' \
  -d '{"strategy":[{"tool":"block_ip","params":{"ip":"192.168.57.199"}}],
       "attack_mode":"sqli","red_vm":"kali","blue_vm":"target"}' | python -m json.tool
```

Compare with a no-op strategy (an empty tool list) — `rs_attack` should be
higher, because nothing was defended.

## 7. Unit tests (no virtual machines needed)

```sh
pip install -r requirements/test.txt        # pytest is not in the runtime manifests
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q
```

A bare `pytest` collects two suites:

| Suite | Covers |
|---|---|
| `tests/` | the repository contract (`check_repo_contract.py`) plus the lab-side tests — attack-probe stages, the `[RESULT]` contract, and the summariser's entry-point byte-identity |
| `training/tests/` | the four-stage cascade reward, its polarity, and the SA-GRPO configuration assertion |

**All tests pass**, with exactly one skip — the opt-in check against a real
captured `fast.log`, enabled with `SECLOOP_REAL_FASTLOG=<path>`. (The count moves
as tests are added; read it off your own run.) Nothing here needs a VM, PHP, MySQL,
Suricata or a model endpoint.

`PYTHONDONTWRITEBYTECODE=1` is **required** for a clean tree, not merely nice to
have. Measured on a clean checkout, running the suite without it leaves exactly one
directory behind — `__pycache__/conftest.cpython-3xx-pytest-*.pyc` — because pytest's
assertion rewriter compiles the root `conftest.py` before that file can set
`sys.dont_write_bytecode = True`. `tests/test_repo_contract_gate.py` then runs
`tests/check_repo_contract.py` against the live tree and fails with `bytecode present`,
which reads like a repository failure but is a side effect of the run.

Tests that spawn child interpreters are a second source: a child does
not inherit `sys.dont_write_bytecode`; they pass `-B` themselves, so they
cannot dirty the tree either way. `__pycache__/` is gitignored regardless.

## 8. Tear down

```sh
cd vagrant && vagrant destroy -f
```

The target is disposable by design; destroy it rather than reusing it.
