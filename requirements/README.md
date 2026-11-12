# Dependency manifests

Dependencies are split by subsystem so you only install what you need.

| File | For | Install |
|---|---|---|
| `battlefield.txt` | the SOC / orchestration subsystem (`battlefield/`, `ids/`) | `pip install -r requirements/battlefield.txt` |
| `../agent/requirements.txt` | the strategy-generation agent (`agent/`) | `pip install -r agent/requirements.txt` |
| `../training/requirements.txt` | SA-GRPO training (`training/`) | `pip install -r training/requirements.txt` |
| `test.txt` | the offline test suite (no VM, no model) | `pip install -r requirements/test.txt` |

## Notes

**`requests` is pinned once.** `battlefield.txt` and `agent/requirements.txt` both
pin `requests==2.34.2`; the training manifest takes a floor (`>=2.31.0`) because it
shares an environment with TRL and torch. Two *different* exact pins used to coexist
(`2.32.3` here, `2.34.2` in the agent), so installing one subsystem and then the
other silently swapped the HTTP stack that the SOC client runs on.
`tests/lab/test_contract_constants.py` fails if the exact pins diverge again.

**Tests need `test.txt`.** `docs/quickstart.md` section 7 runs `python -m pytest -q`,
and no runtime manifest declares pytest -- only `training/setup.py`'s `tests` extra
does, which nothing installs. Install `requirements/test.txt` first, or the
repository's only self-check fails on a fresh machine.

**Python version.** The project targets **Python 3.11**. Note that the `requests`
pin above is `>=3.10` software (2.34.x dropped 3.9), so a 3.9 interpreter cannot
satisfy this manifest — 3.11 is the tested target, 3.10 is the floor.

**TRL is a dependency, not vendored code.** The training subsystem depends on
HuggingFace TRL pinned to the upstream revision
`1bca49515ecd5b85d16e68c42c76670e252e19f1` (equivalently `trl==0.18.0`). Earlier
internal versions copied the entire TRL package into the repository; that made
the SA-GRPO changes impossible to see and created a licence-notice problem,
because the vendored copy shipped Apache-2.0 sources without their licence
file. Depending on the upstream package instead keeps the diff to five
configuration values, all visible in
`training/recipes/Qwen2.5-7B-Instruct/grpo/config.yaml`.

**The lab does not need Python packages on the host.** The two virtual machines
install their own dependencies during `vagrant up`; see
`vagrant/provision/`.

**No credentials are stored here.** Anything that needs a secret reads it from
an environment variable.
