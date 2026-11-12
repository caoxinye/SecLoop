# `ids/` — the alert summariser (paper Eq. 2)

Compresses real Suricata `fast.log` alerts into **section `C`** of the prompt
`P = [C, T_A, E]` (`docs/INTERFACES.md` §8/§9). This directory holds one module:

| File | Role |
|---|---|
| `combine_ids_log.py` | parse → group → render; the single owner of `C` |

## Public API

```python
from ids.combine_ids_log import parse_fastlog_line, summarize_fastlog, summarize_lines

summarize_fastlog(path_or_Path, window_s=300) -> str   # reads a file
summarize_lines(lines, window_s=300) -> str            # takes already-split lines
```

`summarize_fastlog` and `summarize_lines` are **byte-identical for the same content**
through every entry point (path, `Path`, `str`, stdin, LF and CRLF). The RTC, the agent
and the training path all reach the summariser differently, so this is a contract, not
a nicety (`docs/INTERFACES.md` §9).

## CLI

```sh
python ids/combine_ids_log.py --fastlog /path/to/fast.log        # C on stdout
python ids/combine_ids_log.py -f - --window-s 60                # stdin
```

| Flag | Default | Meaning |
|---|---|---|
| `--fastlog`, `-f` | `-` (stdin) | path to the log, or `-` |
| `--window-s` | `300` | sliding-window width in seconds |
| `--max-episodes` | `50` | maximum episodes rendered |
| `--max-examples` | `3` | signature variants quoted per episode |
| `--log-level` | `WARNING` | verbosity on stderr |

The summary goes to **stdout**; diagnostics go to stderr.

## Behaviour worth knowing

* Alerts are grouped by `(attack_type, source_ip)` inside a sliding window, so
  near-identical signatures collapse into one episode that still lists its distinct
  variants (`"<family> - <variant>"`).
* An empty or entirely unparsable log yields `""`; a **missing** file raises
  `FileNotFoundError` rather than returning an empty summary.
* Nothing here writes a log. Alerts are only ever read, so the pipeline cannot
  manufacture the evidence it summarises.
* The committed fixture `tests/lab/fixtures/fastlog_parser_fixture.txt` is
  **hand-authored parser input, not captured evidence** — its header says so, and a
  test asserts that banner survives.

## Tests

```sh
PYTHONDONTWRITEBYTECODE=1 python -m pytest tests/lab/test_ids_summarizer.py -q
python tests/lab/test_ids_summarizer.py          # standalone, standard library only
```

An opt-in check against a real captured `fast.log` is enabled with
`SECLOOP_REAL_FASTLOG=<path>`; it is skipped by default.
