# SPDX-License-Identifier: Apache-2.0
"""`C` is paper Eq. 4's `S_r(E)`, or it is an error -- never a silent substitution.

`agent/main.py` compresses a real Suricata `fast.log` into `C` with the shared summariser.
Raw log lines are not `C`: no episode collapsing, no sliding window. A prompt built from
them is not comparable with the paper's recipe while looking entirely normal downstream.

The repository's rule elsewhere is "never degrade silently" (the Eq. 21 judge raises rather
than returning `0.0`), so the substitution is opt-in via `--allow-raw-alerts`, and when it
happens the returned `origin` records it.

No log file, no VM, no network: the summariser seam is monkeypatched.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent import main as agent_main  # noqa: E402


@pytest.fixture()
def fastlog(tmp_path: Path) -> Path:
    path = tmp_path / "fast.log"
    path.write_text(
        '[**] [1:1000001:1] SECLOOP SQLI - time-based blind [**]\n'
        '[Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.57.199:41000 -> 192.168.57.200:80\n',
        encoding="utf-8",
    )
    return path


def _without_summariser(monkeypatch) -> None:
    monkeypatch.setattr(agent_main, "_load_summarizer", lambda: (None, None))


def test_an_unavailable_summariser_fails_by_default(monkeypatch, fastlog) -> None:
    """The flag must be opt-in: the default has to protect the experiment."""
    _without_summariser(monkeypatch)
    with pytest.raises(agent_main.AgentError) as excinfo:
        agent_main.summarize_alerts(fastlog, 300)
    message = str(excinfo.value)
    assert "S_r" in message and "Eq. 4" in message
    assert "--allow-raw-alerts" in message, "the error must say how to override it deliberately"


def test_the_override_uses_the_raw_lines_and_says_so(monkeypatch, fastlog) -> None:
    _without_summariser(monkeypatch)
    summary, origin = agent_main.summarize_alerts(fastlog, 300, allow_raw_alerts=True)
    assert "SECLOOP SQLI" in summary
    assert "allow-raw-alerts" in origin, "a substituted C must be traceable in the run record"


def test_a_working_summariser_is_preferred_and_marked_as_such(monkeypatch, fastlog) -> None:
    calls: list[tuple[str, int]] = []

    def summarise(path: str, *, window_s: int) -> str:
        calls.append((path, window_s))
        return "1 episode: SECLOOP SQLI from 192.168.57.199"

    monkeypatch.setattr(agent_main, "_load_summarizer", lambda: (summarise, "ids.combine_ids_log"))
    summary, origin = agent_main.summarize_alerts(fastlog, 120, allow_raw_alerts=True)
    assert summary.startswith("1 episode")
    assert calls == [(str(fastlog), 120)], "the window has to reach the summariser"
    assert "raw" not in origin


def test_an_empty_summary_is_refused_rather_than_prompted(monkeypatch, fastlog) -> None:
    """INTERFACES §9: never prompt the LLM with no alerts at all."""
    monkeypatch.setattr(
        agent_main, "_load_summarizer", lambda: (lambda path, *, window_s: "   ", "stub")
    )
    with pytest.raises(agent_main.AgentError, match="empty alert summary"):
        agent_main.summarize_alerts(fastlog, 300)


def test_a_missing_log_file_is_named_in_the_error(tmp_path: Path) -> None:
    with pytest.raises(agent_main.AgentError, match="not found"):
        agent_main.summarize_alerts(tmp_path / "absent.log", 300)


def test_the_cli_flag_exists_and_defaults_to_off() -> None:
    """The override has to be reachable from the command line, and off unless asked for."""
    import inspect

    source = inspect.getsource(agent_main)
    assert '"--allow-raw-alerts"' in source
    assert "store_true" in source
    # `allow_raw_alerts` starts false, so `bool(args.allow_raw_alerts)` is the opt-in.
    assert "allow_raw_alerts=bool(args.allow_raw_alerts)" in source
