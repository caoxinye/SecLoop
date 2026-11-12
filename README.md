# SecLoop

**SecLoop** is a framework for fully automated security strategy generation,
orchestration, response and feedback, together with **SA-GRPO**, a
security-aware group relative policy optimization algorithm for tuning the
strategy-generating model.

This repository accompanies the paper:

> X. Cao, Y. Lin, G. Nan, et al., "Advancing LLM-Based Security Automation With
> Customized Group Relative Policy Optimization for Zero-Touch Networks,"
> *IEEE Journal on Selected Areas in Communications*, vol. 44, 2026, pp. 2669–2686.
> DOI: [10.1109/JSAC.2025.3643844](https://doi.org/10.1109/JSAC.2025.3643844)

See [README.zh-CN.md](README.zh-CN.md) for a Chinese overview.

---

## Architecture

SecLoop closes an observe → orient → decide → act → feedback loop across three
subsystems that communicate over HTTP:

```
┌──────────────────────────────────────────────────────────────────────────┐
│  vagrant/  ──  isolated lab network 192.168.57.0/24  (VMware provider)   │
│                                                                          │
│   ┌────────────────────┐            ┌──────────────────────────────────┐ │
│   │  red VM:  kali     │  attack ▶  │  blue VM:  target                │ │
│   │  192.168.57.199    │            │  192.168.57.200                  │ │
│   │  battlefield/      │            │  Apache + PHP + MySQL            │ │
│   │    attacks/        │            │  target/webapp  (vulnerable)     │ │
│   └────────────────────┘            │  Suricata + local.rules          │ │
│                                     └──────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
        ▲                                                        │
        │ red-team controller                                    │ alerts
        │                                                        ▼
┌───────┴──────────────┐        ┌───────────────┐        ┌──────────────────┐
│ battlefield/soc       │        │ agent/        │        │ ids/             │
│  red_team_controller  │◀──────▶│  LLM strategy │◀───────│  summarizer S_r  │
│  blue_team_controller │        │  generation   │        │  (Eq. 2)         │
│  policy_execution_    │        └───────┬───────┘        └──────────────────┘
│    validator (PEV)    │                │
│  iac_generator        │        ┌───────▼───────┐
└───────────┬───────────┘        │ training/     │
            │                    │  SA-GRPO      │
            └── feedback vector ─┤  cascade      │
               {rs_exe, rs_attack │  reward       │
                rs_service, F_i}  └───────────────┘
```

### Feedback vector

Per the paper (Eqs. 10–13), one evaluation round yields

| Field | Meaning | Range |
|---|---|---|
| `rs_exe` | fraction of the strategy's tools that deployed successfully (Eq. 10) | `[0, 1]` |
| `rs_attack` | fraction of the attack's stages that still succeeded (Eq. 11) — **a high value means the defence did not hold** | `[0, 1]` |
| `rs_service` | service availability after the strategy was applied (Eq. 12) | `{0, 1}` |
| `F_i` | `rs_exe + rs_attack + rs_service` (Eq. 13) | `[0, 3]` |

`rs_attack` is reported as a **raw measurement**. The reward layer derives defence
effectiveness as `1 - rs_attack` — this repository's estimator of Eq. 20's
`W_BATTLE-FIELD` ("absence of warning alarms"; the paper names the term without giving an
estimator). Blocking the attack earns the point, with no further condition, so `rs_service`
is no longer a gate on it. It is still measured, reported, and counted in `F_i` (Eq. 13) —
but **`F_i` is not part of the reward total**, so nothing in the reward stops a strategy that
"defends" by breaking the target; only the Eq. 21 judge (and human review of the logs) does.
Measurement and polarity are deliberately kept in separate layers; see
`docs/INTERFACES.md` §4 and §10.2.

### SA-GRPO

SA-GRPO is GRPO with **five** configuration values, all expressed as configuration of
the underlying GRPO trainer rather than bespoke objective code:

| Setting | Value | Effect |
|---|---|---|
| `scale_rewards` | `false` | advantage is not divided by the group standard deviation |
| `beta` | `0.0` | KL term removed |
| `epsilon` / `epsilon_high` | `0.2` / `0.28` | asymmetric Clip-Higher |
| `num_generations` | `7` | group size *G* |
| `loss_type` | `dr_grpo` | Eq. 14 normalises by `1/G` only, with no per-sequence length factor |

Rewards are a four-stage cascade: format → execution → evaluation → penalty
(Eqs. 18–21), implemented in `training/src/open_r1/rewards.py`.

---

## Repository layout

| Path | Contents |
|---|---|
| `vagrant/` | two-VM lab (Kali attacker + Ubuntu target), Infrastructure-as-Code |
| `target/` | the reference target: a small deliberately vulnerable web app, plus Suricata rules |
| `battlefield/` | the SOC — red/blue team controllers, policy execution validator, IaC generator, SOC server, and the reference SQLi probe |
| `agent/` | LLM strategy generation, tool bindings, and CLI (the tool *table* lives in `battlefield/soc/tool_catalogue.py`) |
| `ids/` | alert summarizer `S_r` (Eq. 2) |
| `training/` | SA-GRPO training entrypoint, cascade reward, recipe |
| `docs/` | interface contract, architecture, quickstart, reproduction guide |
| `tests/` | unit tests that need no virtual machines |

---

## Requirements

| Component | Version | Notes |
|---|---|---|
| VMware Workstation Pro | **17.6 or later** recommended | Free of charge for commercial, educational and personal use; no licence key required. 17.5.2 also works under the earlier personal-use grant. |
| Vagrant | 2.4.x | |
| `vagrant-vmware-desktop` plugin | 3.x | plus the `vagrant-vmware-utility` service |
| Python | 3.11 | |
| RAM / disk | ≥ 8 GB free RAM for the two VMs; ~6 GB for base boxes | |

Base boxes (downloaded by Vagrant on first `vagrant up`):

- `kalilinux/rolling` — the attacker VM
- `bento/ubuntu-18.04` — the target VM

### Model serving endpoint

The strategy-generating model is served **locally** and consumed through the
standard OpenAI-compatible serving protocol (as implemented by vLLM, SGLang,
TGI, Ollama and similar servers). The same endpoint abstraction is used by both
the inference path (`agent/`) and the training path (`training/`), so a single
served model can back evaluation and training alike.

Point `agent/config.json` at your served model:

```json
{
  "llm": {
    "base_url": "http://127.0.0.1:8000/v1",
    "model": "<served-model-name>",
    "api_key_env": "LLM_API_KEY"
  }
}
```

`api_key_env` names an environment variable; no credential is stored in this
repository. Verify connectivity with:

```sh
python -m agent.llm.llm_interface --check
```

No model weights are distributed with this repository.

---

## Quickstart

```sh
# 1. bring up the isolated lab (downloads the two base boxes on first run)
cd vagrant && vagrant up

# 2. install the SOC-side dependencies
pip install -r requirements/battlefield.txt

# 3. start the SOC server (port 8988)
python battlefield/soc_server.py

# 4. in another terminal, run one full loop against the lab
python agent/main.py --ids-summary-file /path/to/fast.log
```

The reference loop and its expected output are described in
[docs/quickstart.md](docs/quickstart.md); the interface contract that all
subsystems share is in [docs/INTERFACES.md](docs/INTERFACES.md).

---

## Ethics and responsible use

This repository does **not** distribute the full attack corpus used in the
paper's evaluation, nor any weaponized exploit targeting third-party systems —
providing such material would be irresponsible. What we provide is a single,
self-contained reference scenario: a deliberately vulnerable web application
written by us, running entirely within an isolated lab network, together with
the minimal SQLi probe required to exercise the SecLoop feedback loop
end-to-end. Never expose the lab network to the internet.

See [SECURITY.md](SECURITY.md) for the mandatory operating constraints.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE). Third-party components and their
terms are listed in [NOTICE](NOTICE).

## Citation
If you find our code useful for your research, please consider citing our paper:
```bibtex
@article{cao2026secloop,
  author  = {Cao, Xinye and Lin, Yihan and Nan, Guoshun and others},
  title   = {Advancing {LLM}-Based Security Automation With Customized Group
             Relative Policy Optimization for Zero-Touch Networks},
  journal = {IEEE Journal on Selected Areas in Communications},
  volume  = {44},
  pages   = {2669--2686},
  year    = {2026},
  doi     = {10.1109/JSAC.2025.3643844}
}
```
