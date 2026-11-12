# Running and extending SecLoop

Two things are runnable from this repository:

1. **the reference scenario** — the complete SecLoop feedback loop against the
   bundled lab; and
2. **the training recipe** — SA-GRPO on a dataset supplied by you in the
   documented format.

For the step-by-step walkthrough of the reference scenario, see
[quickstart.md](quickstart.md). For the exact interfaces, see
[INTERFACES.md](INTERFACES.md).

---

## 1. Reference scenario

```sh
cd vagrant && vagrant up
pip install -r requirements/battlefield.txt
python battlefield/soc_server.py
python agent/main.py --ids-summary-file /tmp/fast.log
```

What is genuinely exercised end-to-end:

| Stage | Mechanism |
|---|---|
| attack | `battlefield/attacks/sqli_lab.py` performs real time-based blind SQLi against the lab target |
| detection | Suricata on the target inspects the real HTTP traffic and writes a real `fast.log` |
| summarisation | `ids/combine_ids_log.py` compresses that log into the prompt's `C` |
| decision | `agent/` asks the locally served model for a JSON tool-call strategy |
| orchestration | the **whole strategy** is deployed on the blue VM exactly once |
| attack replay | the attack runs exactly once against the defended target |
| measurement | `policy_execution_validator.py` computes `rs_exe`, `rs_attack`, `rs_service`, `F_i` |

Every alert in that path originates from the IDS observing real traffic. No log
lines are fabricated anywhere in the pipeline.

### Sanity checks worth running

- **Defence has an effect.** Compare a `block_ip` strategy against an empty
  strategy: with the empty strategy `rs_attack` stays high, with `block_ip` it
  drops while `rs_service` remains `1`.
- **The validator is arithmetic.** `python -m pytest tests -q` covers the
  three-signal computation, including the case where the attacker produced no
  stages.

### Configuration points

| What | Where |
|---|---|
| lab IPs, box names, provider | `vagrant/Vagrantfile` |
| attack registry (`sqli` only) | `battlefield/soc/attack_commands.json` |
| SOC port / VM pool | environment, defaults in `battlefield/soc_server.py` (`SOAR_VM_POOL`) |
| model endpoint | `agent/config.json` |

---

## 2. Training with SA-GRPO

### Recipe

`training/recipes/Qwen2.5-7B-Instruct/grpo/config.yaml` carries the paper's
settings, including the five knobs that define SA-GRPO:

```yaml
num_generations: 7        # group size G
scale_rewards: false      # no standard-deviation division in the advantage
beta: 0.0                 # KL term removed
epsilon: 0.2              # lower clip bound
epsilon_high: 0.28        # Clip-Higher
loss_type: dr_grpo        # no per-sequence length normalisation — see below
reward_funcs:
  - sa_cascade
```

These are explicit on purpose. The algorithm's behaviour is entirely determined
by configuration plus the reward functions — no trainer code is patched — so a
reader can see the whole definition of SA-GRPO in one file.

`loss_type` deserves a note because the paper's Table IV does not list it. The
paper's objective (Eq. 14) is written as

```
J(θ) = E[ (1/G) · Σ_i Σ_t min( γ_i,t·Â_i,t , clip_i,t·Â_i,t ) ]
```

— the denominator is `1/G` only, with **no `1/|o_i|` factor**, i.e. no
per-sequence length normalisation. Of TRL's three loss formulations, only
`dr_grpo` has that property (`bnpo`, the upstream default, normalises by the
batch token count; `grpo` divides by each sequence length). It is also what the
authors' original training run used. Writing it down rather than inheriting a
library default keeps the recipe faithful to Eq. 14 and makes the choice visible.

### Why eight GPUs, seven ranks

At the pinned TRL revision, training hard-fails unless

```
per_device_train_batch_size × num_processes × gradient_accumulation_steps
```

is divisible by `num_generations`. With the paper's `4 × N × 1` and `G = 7`,
`N` must be a multiple of 7 — which is exactly why the paper's 8×A800 node runs
**seven training ranks plus one GPU reserved for the generation server**
(`use_vllm: true` requires a separate `trl vllm-serve` process). The launcher and
its accelerate config encode this.

`use_vllm` is `false` by default so the recipe starts without a generation
server; flip it to `true` and start the server on the spare GPU as documented in
`training/README.md`. `vllm_server_host` / `vllm_server_port` use the same
endpoint convention as `agent/config.json`.

### Running it

```sh
cd training
pip install -r requirements.txt
bash train.sh
```

`train.sh` launches `accelerate` with the DeepSpeed ZeRO-2 configuration and the
recipe above. It reads all credentials from the environment; nothing is
hardcoded. You need to supply:

- a **served model** for the reward cascade's penalty stage (the same endpoint
  abstraction the agent uses); and
- a **training dataset** in the format described below.

### Dataset format

The training entrypoint expects a JSON list. Each record carries the alert
evidence that forms the prompt's `C` and `E` sections:

```json
[
  {
    "alerts": "<raw alert text for this sample>",
    "attack_mode": "sqli",
    "platform": "Ubuntu",
    "description": "<human-readable environment description>",
    "tools": ["bash", "block_ip"],
    "red_vm_name": "kali",
    "blue_vm_name": "target"
  }
]
```

`alerts` is compressed by the summariser into `C`; `platform` and `description` supply the
`E` line; `tools` supplies **both** `E`'s "Available tools" list and `T_A`. Those two
sections are read from the *same* row and therefore cannot disagree — which is the point:
paper Eq. 3 defines `T_A` as the tools available in the current environment, and rendering
it from the full catalogue instead of the row puts a Windows-only tool on a Linux prompt
(see [INTERFACES.md](INTERFACES.md) §6).

The VM pair is resolved **separately**, by `read_vm_config()`, in this order:
`SOAR_RED_VM`/`SOAR_BLUE_VM`/`SOAR_ATTACK_MODE`, then the **first record** of the corpus
(`red_vm_name`/`blue_vm_name`/`attack_mode`), then the [INTERFACES.md](INTERFACES.md) §1
constants. It is *not* per-row — every row is evaluated in the same lab environment. A
corpus that omits those keys is unusable unless the environment pins all three; training
refuses to start rather than silently scoring format only.

Point the recipe's `dataset_name` at your file, then run `train.sh`.

No dataset or trained weights are distributed with this repository.

---

## 3. Extending the framework

### Adding an attack scenario

1. Add an entry to `battlefield/soc/attack_commands.json` with the command to
   run on the red VM and the stage names/weights it will report.
2. Make that command print a single `[RESULT] {…}` JSON line — see
   [INTERFACES.md](INTERFACES.md) §2.
3. Add a Suricata rule for it in `target/suricata/local.rules` so the IDS
   actually observes it. Number it with the next free `sid` in the local range
   (continuing from `1000001`); there is no upper bound to raise — the contract
   asks for **at least** six rules, consecutive from that start.
4. Provision the corresponding target in `vagrant/provision/`.

The validator needs no changes: it consumes stage results generically.

### Adding a tool

**One table, plus one binding.** There is no second table to keep in sync
([INTERFACES.md](INTERFACES.md) §6):

1. `battlefield/soc/tool_catalogue.py` — add a `ToolSpec` to `TOOL_CATALOGUE`: name,
   one-sentence description, parameters, the shell `template`, `privileged`, the
   `renderer` it needs (`posix` or `powershell`), and what to **probe for**:
   `requires_any` (executables, at least one must exist) and `requires_root`. Do **not**
   add a per-OS list — a table cannot know what a particular machine has installed; the
   probe decides (paper Eq. 3). The detection script is generated from these declarations,
   so a new requirement is picked up automatically. This is the only tool table in the
   repository; the SOC's command renderer and the agent's `T_A` both read it.
2. `agent/tools/security_tools.py` — add the client-side `func` (and an optional
   validator) to `_IMPLEMENTATIONS`. The module fails **at import** if the catalogue and
   these bindings are not 1:1, so a missing binding is a loud error rather than a lower
   `rs_exe` that reads like a model problem.

Then check that the tool actually shows up, instead of assuming it — the answer depends on
the machine, so ask the machine:

```sh
curl -s http://127.0.0.1:8988/capabilities   # is the new tool in available_tools?
```

It appears only if the target satisfies its declared requirements; `unavailable` will say
exactly what was missing. To inspect the prompt without a running SOC, declare the tools
(`--tools`, labelled `tool_source="declared"`) rather than editing a config list:

```sh
PYTHONPATH=. python -m agent.main --print-prompt --tools block_ip,bash \
  --ids-summary-file tests/lab/fixtures/fastlog_parser_fixture.txt | grep -A4 'Available tool'
```

A tool whose requirements the target does not meet is deliberately absent from `T_A` and
the SOC refuses it, so that the model is never invited to call something the environment
cannot run (paper Eq. 3).

### Replacing the target

Any host works as long as (a) it is on the isolated lab network, (b) the SOC can
reach it over Vagrant SSH, and (c) its service-availability anchor answers on
`index.php` **with the expected marker** — `rs_service` requires the marker by
default, so either keep a `SecLoop target OK` body, point the probe at your own
anchor with `SOC_TARGET_MARKER`, or relax it with `SOC_TARGET_MARKER_STRICT=0`.
See [target/README.md](../target/README.md).

---

## 4. Troubleshooting

| Symptom | Likely cause |
|---|---|
| the round ends `success: false` with `feedback: null` and an error mentioning `[RESULT]` | **the attack was not measurable** — no parsable `[RESULT]` line, an empty stage list, a dead VM or a failed snapshot restore. This is deliberate: the SOC refuses to report `rs_attack = 0.0`, because that value already means "the defence held" ([INTERFACES.md](INTERFACES.md) §4.1). Check the probe's stdout on the red VM |
| `rs_attack` is `0.0` **with two or more stages reported** | the attack ran and every stage failed: that is a genuine successful defence |
| `rs_service` is always `0` | the target's `index.php` is not answering, or it answers without the `SecLoop target OK` marker — the marker is required by default; see [target/README.md](../target/README.md) |
| CPython `SyntaxError` on import anywhere | you are on an older checkout; every module must `ast.parse` cleanly |
| solver: `apt-get update` fails inside the target VM | the bionic archive moved; `target_setup.sh` rewrites sources to `old-releases.ubuntu.com` automatically, re-run `vagrant provision` |
| model endpoint errors | `python -m agent.llm.llm_interface --check` reports the exact failure |
| `vagrant up` aborts with *"would collide with another device"* | another product owns `192.168.56.0/24` — that is VirtualBox's **default** host-only subnet. This repo uses `192.168.57.0/24` for exactly that reason; see `INTERFACES.md` §1.1 before changing it |
| `The provider 'vmware_desktop' could not be found ... Vagrant knows about the following providers: docker, hyperv, virtualbox` | **`VAGRANT_HOME` is unset or points elsewhere**, so Vagrant cannot see the `vagrant-vmware-desktop` plugin. This is not a missing plugin. Export the home the plugin was installed under — e.g. PowerShell: `$env:VAGRANT_HOME='D:\vagrant.d'` — and re-run the same command |
| `vagrant status` insists the machine needs "a provider that exists" | same cause as the row above; `vagrant status` rejects `--provider`, so `VAGRANT_HOME` is the fix, not a flag |
| the guests can reach each other but **the host cannot** reach `192.168.57.200` | the host-only vmnet for the lab subnet has no host address (see below) |
| the red VM has no address on the lab network | Vagrant's private-network step does not configure `kalilinux/rolling`; `attacker_setup.sh` assigns `192.168.57.199` itself. Re-run `vagrant provision kali` |

### The host cannot reach the guests

Symptom: `kali` ↔ `target` work (`curl http://192.168.57.200/index.php` from
inside `kali` returns 200), but from the **host** the same URL times out, and the
VMware host-only adapter for the lab subnet shows a link-local `169.254.x.x`
address instead of `192.168.57.1`.

Check it:

```powershell
(Get-NetIPAddress -InterfaceAlias 'VMware Network Adapter VMnet4' -AddressFamily IPv4).IPAddress
# expected: 192.168.57.1     wrong: 169.254.x.x
```

Cause: the host-only vmnet backing the lab subnet exists but was never given its
host address, so the host has no route to `192.168.57.0/24`. This happens before
any SecLoop code runs, and configuring it needs **Administrator** rights.

Fix (Windows, Administrator):

1. Open **Virtual Network Editor** (`vmnetcfg.exe`, or *Edit → Virtual Network
   Editor* in VMware Workstation) and click *Change Settings* to elevate;
2. select the vmnet that backs the lab subnet (here `VMnet4`);
3. set it to **Host-only**, subnet IP `192.168.57.0`, mask `255.255.255.0`;
4. tick *Connect a host virtual adapter to this network*;
5. apply, then re-run `vagrant reload`.

Verify with the one-liner above: it must print `192.168.57.1`. Note this is a
property of the machine's VMware networking, not of the box — a fresh machine
with healthy VMware networking configures the vmnet automatically and the step is
unnecessary.
