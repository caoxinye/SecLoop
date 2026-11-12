# Architecture

This document describes how the subsystems fit together. The **normative
interface contract** — exact endpoints, JSON shapes, field names and polarity
rules — lives in [INTERFACES.md](INTERFACES.md); this file is the explanation
around it.

## 1. The loop

SecLoop implements an observe → orient → decide → act → feedback cycle, mapped
onto the ETSI ZSM logical functions.

```
  plan (VM)                   decide (LLM)              act (SOC)          observe (lab)
┌──────────────┐          ┌────────────────┐        ┌──────────────┐    ┌──────────────┐
│ target/webapp│          │   agent/       │        │ battlefield/ │    │  vagrant/    │
│ deliberately │  alerts  │  prompt        │ strategy│  BTC deploy  │    │  red + blue  │
│ vulnerable   │ ───────▶ │  P=[C,T_A,E]   │ ─────▶ │  RTC attack  │──▶ │  VMs +       │
│ + Suricata   │          │  JSON tool calls│        │  PEV measure │    │  Suricata    │
└──────────────┘          └────────────────┘        └──────┬───────┘    └──────────────┘
        ▲                          ▲                       │
        │                          │                       │ feedback F_i
        │                    ┌─────┴──────┐                │
        │                    │ training/  │◀───────────────┘
        └─────── replay ─────│ SA-GRPO    │   cascade reward
                             └────────────┘
```

1. **Observe.** Suricata on the target VM inspects real HTTP traffic and writes a
   real `fast.log`. Nothing is synthesised.
2. **Orient.** `ids/combine_ids_log.py` compresses the raw log into a structured
   alert summary — the `C` of the paper's Eq. (2).
3. **Decide.** `agent/` builds the prompt `P = [C, T_A, E]` (Eq. 4) and asks the
   served model for a JSON array of tool calls.
4. **Act.** `battlefield/soc_server.py` deploys the **whole strategy** on the blue
   VM exactly once, then runs the attack exactly once (paper Eqs. 8–9).
5. **Feedback.** `policy_execution_validator.py` measures the three signals and
   their sum (Eqs. 10–13). `training/` turns them into a reward (Eqs. 18–21).
6. **Update.** SA-GRPO computes group-relative advantages and updates the policy.

## 2. Subsystems

### `vagrant/` and `target/` — the lab

A two-VM VMware lab: `kali` (attacker, `192.168.57.199`) and `target`
(defender, `192.168.57.200`). The target runs Apache + PHP + MySQL plus the
reference web application in `target/webapp/`, which concatenates user input
into SQL **on purpose**. Suricata, configured by `target/suricata/local.rules`,
watches the target's HTTP traffic.

The lab is intentionally isolated and intentionally insecure. See
[SECURITY.md](../SECURITY.md).

### `battlefield/` — the SOC

| Component | Role |
|---|---|
| `soc/red_team_controller.py` | launches the attack on the red VM and parses its staged result |
| `soc/blue_team_controller.py` | deploys the whole strategy on the blue VM, one result per tool; restores snapshots |
| `soc/policy_execution_validator.py` | computes `rs_exe`, `rs_attack`, `rs_service`, `F_i` |
| `soc/iac_generator.py` | renders the Vagrantfile for the scenario |
| `soc/attack_commands.json` | attack registry — `sqli` only, no dangling entries |
| `soc_server.py` | Flask API on port `8988`: `POST /execute_ability`, `GET /health`, `GET /pairs` |
| `attacks/sqli_lab.py` | the reference probe: time-based blind SQLi with binary search, five weighted stages |

### `agent/` — strategy generation

One vendor-neutral client for the served model, a tool registry that is the
single source of truth for the three tools, and a CLI. The prompt contains three
sections — the alert summary `C`, the tool catalogue `T_A`, and the environment
description `E` — matching the training-side prompt.

### `training/` — SA-GRPO

The cascade reward (`R_format + R_exec + R_eva − P`, Eqs. 18–21), the recipe, and
a thin trainer wrapper that asserts the five SA-GRPO configuration values are
actually set. The training entrypoint reads its configuration through
`TrlParser`, so every SA-GRPO knob is visible in the recipe YAML rather than
hidden in patched library code.

## 3. Measurement versus polarity

This is the single most important convention in the codebase.

`policy_execution_validator.py` is a **measurement** component. It reports
`rs_attack` as the fraction of attack stages that succeeded. If the defence
works, the attack fails, so `rs_attack` goes **down** — that is the correct
reading of Eq. (11).

The **polarity** lives in the reward layer as `R_eva = 1 - rs_attack`: **blocking the
attack earns the point**, with no further condition. That is how Eq. (20)'s
`R_eva = W_BATTLE-FIELD` — the paper's "absence of warning alarms" — is evaluated here.
`rs_service` is deliberately not a factor at this stage: folding §IV-D's "and does not cause
any disruption" into Eq. (20) would make the reward conditional on the service, which Eq. (20)
itself does not do. The cost is stated rather than hidden: a strategy that defends by
breaking the service also scores the point. `rs_service` is still measured, still reported,
and still enters `F_i` (Eq. 13) — but **`F_i` is not in the reward total**, so the only
reward-side check on over-defence is the Eq. 21 judge (plus human review of the logs).
Keeping measurement and polarity separate means:

- the validator can be unit-tested purely as arithmetic;
- a reader can always ask "what did we actually measure?" and get one answer;
- there is no risk of an accidental double inversion.

A related guard: if the attacker produced no stages at all (it crashed, timed
out, or its output could not be parsed), `rs_attack` is `0.0` and a warning is
logged. It is never set to a maximum value.

## 4. Tool registry

The catalogue holds exactly three tools. It records **what each tool needs**, and the SOC
**probes the target** to learn what is actually there — paper Eq. 3 defines `T_A` as the
tools available in the current environment, so the environment has to be asked:

| Tool | Parameters | Effect on the blue VM | Needs | `privileged` |
|---|---|---|---|---|
| `block_ip` | `ip` | `iptables -I INPUT -s <ip> -j DROP` | a `posix` session, `iptables`, working `sudo -n` | yes |
| `bash` | `command` | run the command | a `posix` session, `bash` or `sh` | no |
| `powershell` | `command` | run the command | a PowerShell session, `pwsh`/`powershell` | no |

`GET /capabilities` runs one probe over SSH (`uname -s`, `sudo -n true`, then
`command -v` for every requirement the catalogue declares) and derives the offered set
from the result:

| Probed environment | `T_A` |
|---|---|
| Linux, `iptables`, root | `block_ip, bash` |
| Linux, only `sh`, no root | `bash` |
| Linux, `iptables`, **no root** | `bash` |
| Linux, nothing installed | *(empty — the agent refuses to build a prompt)* |
| Windows, `powershell` | *(empty — this SOC cannot drive a PowerShell session)* |

The same code therefore yields a different `T_A` per machine, which a per-OS table could
never do: it cannot know whether *this* box has `iptables` or a working `sudo`. A second
list kept anywhere else — in the agent, in the SOC, or as a `tools` array in
`agent/config.json` — is free to disagree, and a Linux prompt then advertises a
Windows-only tool that the SOC "executes" through `bash -lc`, crediting a defence that
never happened.

`battlefield/soc/tool_catalogue.py` is the single table: the SOC renders its commands from
it and enforces the probed set, the agent binds implementations to it and renders `T_A`
from it, and the training tree re-exports that view rather than keeping a copy.

## 5. Model serving

The strategy model is served locally and consumed through the standard
OpenAI-compatible serving protocol. Inference (`agent/`) and training
(`training/`) share one endpoint abstraction, so a single served model backs
both. No weights and no credentials are distributed with this repository.
