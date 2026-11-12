# IDS corpus for SA-GRPO training

`training/src/open_r1/grpo.py` reads `security_dataset.json` from this directory
(override with the `dataset_dir` recipe key or the `SECLOOP_DATASET_DIR`
environment variable; `SOAR_DATASET`, used by the SOC transport, may point at the
same file).

The file is **not** committed. It is produced from real Suricata output by the IDS
pipeline (`ids/`, `INTERFACES.md` §9/§11) on the testbed this repository describes;
fabricating alert lines is explicitly out of bounds (`INTERFACES.md` §0), and a corpus
captured on a different testbed is not reproducible.

## Expected schema

One JSON array; every row is an object with at least:

| key | type | used for |
|---|---|---|
| `alerts` | string | **raw Suricata `fast.log` text** for that attack window, one alert line per line; the summarizer compresses it into the prompt's `C` section (required by the `sa_cascade` reward signature) |
| `platform` | string | `E` section: target platform |
| `description` | string | `E` section: environment description |
| `tools` | list of strings | `E` section: tools available in that environment |

### Why the raw log text and not a summary

The `C` section is produced by `ids/combine_ids_log.py`, which `INTERFACES.md` §9
names as the single authority for `S_r`. `training/src/open_r1/utils/summarizer.py`
re-exports it, so the `C` the model sees during training is rendered by exactly the
same code as the `C` on the evaluation path. Storing a *pre-aggregated* digest
instead would render the training prompt with a different grammar from the
evaluation prompt.

A row whose `alerts` text contains no parsable `fast.log` line summarises to `""`;
`grpo.py` drops such rows and logs how many were dropped, because a prompt without
a `C` section must never be sent to the model (`INTERFACES.md` §8).

The legacy digest grammar (`Time range: ... detected N times '<signature>' attack,
source IP: ..., target: ..., risk level: N`) is not the dataset contract;
`parse_legacy_digest()` in `training/src/open_r1/utils/summarizer.py` exists only to
inspect such a file explicitly.

Optional: `security_dataset_test.json` with the same schema. When it is missing the
train split is reused for evaluation and a warning is logged, because an
evaluation number computed on the training rows would be meaningless.

## Regenerating

```bash
# 1. capture the real fast.log slice for one attack window (red team runs the attack,
#    Suricata writes the alerts) and keep those lines verbatim in `alerts`.

# 2. preview the C section the model will actually see for that row:
python ids/combine_ids_log.py --fastlog <path/to/fast.log>            # C on stdout
python ids/combine_ids_log.py --fastlog <path/to/fast.log> --window-s 300

# 3. run the training pipeline end to end and check the rows that were dropped:
PYTHONPATH=src python -m open_r1.grpo --config recipes/Qwen2.5-7B-Instruct/grpo/config.yaml
```

`PYTHONPATH=src` is required unless you installed the package (`pip install -e .`):
`pip install -r requirements.txt` alone does not put `open_r1` on the import path.
`training/train.sh` exports it itself, which is why the same command works there.

`ids/combine_ids_log.py` writes its summary to stdout and takes `--fastlog/-f`
(a path, or `-` for stdin), `--window-s`, `--max-episodes`, `--max-examples`,
`--log-level`. See `ids/README.md` for the pipeline's own interface.
