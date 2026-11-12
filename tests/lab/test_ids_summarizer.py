# SPDX-License-Identifier: Apache-2.0
"""Offline tests for ``ids/combine_ids_log.py`` -- the Eq.2 alert summarizer.

Runs against ``tests/lab/fixtures/fastlog_parser_fixture.txt``, a small
hand-authored fixture whose expected counts are worked out by hand (see its
header).  No network, no Suricata, no VM, standard library only.

What is covered
---------------
* ``parse_fastlog_line`` on the shapes real Suricata ``fast.log`` emits, including
  a microsecond-less timestamp, a ``(null)`` classification, and a rule message
  that carries no ``"<family> - <variant>"`` discriminator;
* ``"<family> - <variant>"`` collapsing: several near-identical signatures must
  become one episode that still lists its distinct variants -- the whole point of
  compressing alerts into the prompt section ``C``;
* sliding-window grouping by ``(attack_type, source_ip)``, order-independence and
  byte-level determinism;
* ``""`` for empty or entirely unparsable input, and a loud ``FileNotFoundError``
  for a missing log (never a silent empty summary);
* ``summarize_lines`` and ``summarize_fastlog`` are **byte-identical** for the
  same content, through every entry point (path, ``Path``, ``str``, stdin, LF and
  CRLF), because the RTC, the agent and the training path all reach the
  summarizer differently;
* a volume case generated in memory (a 136k-line log is deliberately *not*
  committed);
* an opt-in integration check against a real captured log, enabled with
  ``SECLOOP_REAL_FASTLOG=<path>`` -- skipped by default, and read-only.

What is NOT covered
-------------------
A live Suricata install and its real ``fast.log``.
The committed fixture is a parser fixture, never detection evidence.

Run standalone (stdlib only) or with pytest::

    python tests/lab/test_ids_summarizer.py
    python -m pytest tests/lab/test_ids_summarizer.py -q
"""

from __future__ import annotations

import ast
import io
import ipaddress
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _labkit  # noqa: E402  (path bootstrap must come first)
from _labkit import FASTLOG_FIXTURE, SUMMARIZER_PATH, run_module_tests  # noqa: E402

summarizer = _labkit.load_summarizer()

#: Hand-verified expectations for the fixture (13 alert lines, 6 episodes).
FIXTURE_ALERTS = 13
FIXTURE_EPISODES_300S = 6
FIXTURE_EPISODES_60S = 7
FIXTURE_SOURCES = 3
FIXTURE_TARGETS = 1
FIXTURE_MALFORMED_LINE_MARKER = "this line has no timestamp and must be skipped"


def fixture_lines() -> list[str]:
    return _labkit.read_fixture_lines()


def episodes_in(summary: str) -> int:
    return int(re.search(r"(\d+) attack episode", summary).group(1))


def alerts_in(summary: str) -> int:
    return int(re.search(r"(\d+) alert\(s\)", summary).group(1))


# --------------------------------------------------------------------------- #
# 1. the fixture itself
# --------------------------------------------------------------------------- #


def test_fixture_is_labelled_as_synthetic_and_stays_inside_the_lab_net() -> None:
    """Guard the repo rule: no fabricated alert log, and no third-party addresses."""
    lines = fixture_lines()
    text = "\n".join(lines)
    assert "NOT CAPTURED EVIDENCE" in text, (
        "the fixture banner is load-bearing: it is what stops this file from being "
        "mistaken for a real captured alert log"
    )
    assert re.search(r"Synthetic|hand-authored|HAND-AUTHORED", text, re.I), (
        "the fixture must state that it is hand-authored"
    )
    lab = ipaddress.ip_network("192.168.57.0/24")
    for line in lines:
        for address in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line):
            assert ipaddress.ip_address(address) in lab, (
                f"fixture leaked an address outside the published lab /24: {address}"
            )


def test_fixture_parses_into_the_expected_number_of_alerts() -> None:
    parsed = [line for line in fixture_lines() if summarizer.parse_fastlog_line(line) is not None]
    assert len(parsed) == FIXTURE_ALERTS, f"expected {FIXTURE_ALERTS} alert lines, got {len(parsed)}"


def test_only_blank_banner_and_malformed_lines_are_skipped() -> None:
    skipped = [
        line for line in fixture_lines() if line.strip() and summarizer.parse_fastlog_line(line) is None
    ]
    for line in skipped:
        assert line.lstrip().startswith("#") or FIXTURE_MALFORMED_LINE_MARKER in line, (
            f"unexpected unparsable line: {line[:80]!r}"
        )
    assert any(FIXTURE_MALFORMED_LINE_MARKER in line for line in skipped), (
        "the deliberately malformed line must still be present"
    )


# --------------------------------------------------------------------------- #
# 2. parsing
# --------------------------------------------------------------------------- #


def test_parses_the_real_fastlog_shape_field_by_field() -> None:
    line = (
        "03/26/2025-22:03:25.977231  [**] [1:1000001:1] "
        "SQL Injection Attempt - time-based blind via SLEEP() [**] "
        "[Classification: Web Application Attack] [Priority: 1] {TCP} "
        "192.168.57.199:54228 -> 192.168.57.200:80"
    )
    alert = summarizer.parse_fastlog_line(line)
    assert alert is not None, "a real fast.log shape must parse"
    assert alert.sid == 1000001, alert.sid
    assert alert.src_ip == "192.168.57.199" and alert.src_port == 54228, alert
    assert alert.dst_ip == "192.168.57.200" and alert.dst_port == 80, alert
    assert alert.protocol == "TCP", alert.protocol
    assert alert.priority == 1, alert.priority
    assert alert.classification == "Web Application Attack", alert.classification
    assert alert.target == "192.168.57.200:80", alert.target
    assert alert.attack_type == "SQL Injection Attempt", alert.attack_type
    assert alert.msg.endswith("SLEEP()"), alert.msg
    assert alert.timestamp == datetime(2025, 3, 26, 22, 3, 25, 977231), alert.timestamp


def test_variant_suffix_is_collapsed_but_the_first_separator_wins() -> None:
    def family(msg: str) -> str:
        line = (
            "03/26/2025-22:03:25.000000  [**] [1:1:1] "
            f"{msg} [**] [Classification: C] [Priority: 1] {{TCP}} 1.1.1.1:1 -> 2.2.2.2:2"
        )
        alert = summarizer.parse_fastlog_line(line)
        assert alert is not None
        return alert.attack_type

    assert family("SQL Injection Attempt - time-based blind via SLEEP()") == "SQL Injection Attempt"
    assert family("SQL Injection Attempt - UNION SELECT - encoded variant") == "SQL Injection Attempt"
    assert family("XSS Detected") == "XSS Detected", "no discriminator: the whole message is the family"
    assert family("WEIRD - - - msg") == "WEIRD", family("WEIRD - - - msg")


def test_timestamp_without_microseconds_and_null_classification() -> None:
    line = (
        "04/04/2025-07:11:32  [**] [1:100011:1] XSS Detected [**] "
        "[Classification: (null)] [Priority: 3] {TCP} 192.168.57.199:8090 -> 192.168.57.200:8080"
    )
    alert = summarizer.parse_fastlog_line(line)
    assert alert is not None, "suricata can emit timestamps without microseconds"
    assert alert.timestamp == datetime(2025, 4, 4, 7, 11, 32), alert.timestamp
    assert alert.classification == "(null)", alert.classification
    assert alert.protocol == "TCP" and alert.priority == 3, alert


def test_non_alert_lines_parse_to_none() -> None:
    for line in ("", "   ", "# a comment", "garbage", "-- Suricata banner --", "[**] truncated"):
        assert summarizer.parse_fastlog_line(line) is None, repr(line)


# --------------------------------------------------------------------------- #
# 3. empty input and missing files
# --------------------------------------------------------------------------- #


def test_empty_or_unparsable_input_returns_an_empty_string() -> None:
    assert summarizer.summarize_lines([]) == "", "empty list must give ''"
    assert summarizer.summarize_lines([""]) == "", "blank line must give ''"
    assert summarizer.summarize_lines(["   ", "# banner", "garbage"]) == "", "no alert must give ''"
    assert summarizer.summarize_lines([], window_s=60) == "", "any window: '' for empty input"


def test_empty_fastlog_file_returns_an_empty_string() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp) / "fast.log"
        empty.write_text("", encoding="utf-8")
        assert summarizer.summarize_fastlog(empty) == "", "an empty log is not a summary"
        blank = Path(tmp) / "blank.log"
        blank.write_text("# banner\n\n   \n", encoding="utf-8")
        assert summarizer.summarize_fastlog(blank) == "", "a banner-only log is not a summary"


def test_missing_fastlog_raises_instead_of_returning_an_empty_summary() -> None:
    missing = FASTLOG_FIXTURE.parent / "definitely-not-here.fast.log"
    assert not missing.exists(), f"test precondition: {missing} should not exist"
    try:
        summarizer.summarize_fastlog(missing)
    except FileNotFoundError as exc:
        assert "not found" in str(exc), exc
    else:
        raise AssertionError("a missing fast.log must raise FileNotFoundError, not silently return ''")


# --------------------------------------------------------------------------- #
# 4. grouping, windowing, determinism
# --------------------------------------------------------------------------- #


def test_fixture_groups_into_the_hand_verified_episodes() -> None:
    summary = summarizer.summarize_lines(fixture_lines(), window_s=300)
    header = summary.splitlines()[0]
    assert "Suricata alert summary" in header, header
    assert episodes_in(summary) == FIXTURE_EPISODES_300S, header
    assert alerts_in(summary) == FIXTURE_ALERTS, header
    assert f"{FIXTURE_SOURCES} source IP(s)" in header, header
    assert f"{FIXTURE_TARGETS} target IP(s)" in header, header


def test_first_episode_reports_alerts_targets_variants_and_sids() -> None:
    summary = summarizer.summarize_lines(fixture_lines(), window_s=300)
    first = summary.splitlines()[1]
    assert "'SQL Injection Attempt'" in first, first
    assert "source 192.168.57.199" in first, first
    assert "2025-03-26 22:03:25 -> 2025-03-26 22:03:29" in first, first
    assert "5 alert(s)" in first, first
    assert "targets 192.168.57.200:80 (5 alert(s))" in first, first
    assert "max priority 1" in first, first
    assert "3 signature variant(s)" in first, first
    assert "rule sid 1000001,1000004,1000005" in first, first


def test_other_episodes_keep_their_own_protocol_classification_and_quoting() -> None:
    summary = summarizer.summarize_lines(fixture_lines(), window_s=300)
    assert "Portscan Detected" in summary and "over UDP" in summary, summary
    assert "classification (null)" in summary, "a null classification must survive verbatim"
    assert '"SQL Injection Attempt - \\" or 1=1"' in summary, (
        "a message containing a double quote must be rendered safely, not truncated"
    )


def test_narrower_window_splits_the_burst() -> None:
    wide = summarizer.summarize_lines(fixture_lines(), window_s=300)
    narrow = summarizer.summarize_lines(fixture_lines(), window_s=60)
    assert episodes_in(wide) == FIXTURE_EPISODES_300S, wide.splitlines()[0]
    assert episodes_in(narrow) == FIXTURE_EPISODES_60S, narrow.splitlines()[0]
    assert episodes_in(narrow) > episodes_in(wide)
    assert alerts_in(narrow) == alerts_in(wide) == FIXTURE_ALERTS, "windowing must not lose alerts"


def test_output_is_deterministic_and_order_independent() -> None:
    lines = fixture_lines()
    once = summarizer.summarize_lines(lines, window_s=300)
    assert summarizer.summarize_lines(lines, window_s=300) == once, "repeat calls must be identical"
    assert summarizer.summarize_lines(list(reversed(lines)), window_s=300) == once, (
        "aggregation must not depend on the order lines arrive in"
    )
    alert_lines = [line for line in lines if summarizer.parse_fastlog_line(line) is not None]
    assert summarizer.summarize_lines(alert_lines[:2], window_s=300) != once, (
        "sanity: a different input must produce a different summary"
    )


def test_invalid_arguments_fail_loudly() -> None:
    for window in (0, -5):
        try:
            summarizer.summarize_lines(fixture_lines(), window_s=window)
        except ValueError:
            pass
        else:
            raise AssertionError(f"window_s={window} must raise ValueError")
    try:
        summarizer.summarize_lines(fixture_lines(), max_episodes=0)
    except ValueError:
        pass
    else:
        raise AssertionError("max_episodes=0 must raise ValueError")


def test_prompt_size_guard_caps_episodes_and_variants() -> None:
    summary = summarizer.summarize_lines(fixture_lines(), window_s=300, max_episodes=2, max_examples=1)
    lines = summary.splitlines()
    assert len(lines) == 4, f"header + 2 episodes + suppression notice, got {len(lines)}: {lines}"
    assert "further episode(s) suppressed" in lines[-1], lines[-1]
    # `max_examples` truncates the *quoted* variants but must not change the reported
    # count, and the elided ones must be signalled with how many were dropped.  The
    # assertion is on the exact ``", +2 more"`` marker: a bare ``"+"`` would match
    # almost any episode line and could not fail.
    assert "3 signature variant(s)" in lines[1], lines[1]
    assert ", +2 more" in lines[1], lines[1]


# --------------------------------------------------------------------------- #
# 5. entry-point equivalence (byte-identical output)
# --------------------------------------------------------------------------- #


def test_summarize_lines_and_summarize_fastlog_are_byte_identical() -> None:
    """Every caller reaches the summarizer differently; the bytes must not differ."""
    lines = fixture_lines()
    from_lines = summarizer.summarize_lines(lines, window_s=300)
    from_path = summarizer.summarize_fastlog(FASTLOG_FIXTURE, window_s=300)
    assert from_path == from_lines, "path entry point and lines entry point disagree"

    # the same content handed over as the raw file handle the path branch uses
    with FASTLOG_FIXTURE.open("r", encoding="utf-8", errors="replace") as handle:
        assert summarizer.summarize_lines(handle, window_s=300) == from_path

    # Path vs str
    assert summarizer.summarize_fastlog(str(FASTLOG_FIXTURE), window_s=300) == from_path

    # non-default guards must travel through both entry points
    kwargs = {"window_s": 60, "max_episodes": 3, "max_examples": 1}
    assert summarizer.summarize_fastlog(FASTLOG_FIXTURE, **kwargs) == summarizer.summarize_lines(lines, **kwargs)


def test_all_public_signature_forms_agree() -> None:
    lines = fixture_lines()
    expected = summarizer.summarize_lines(lines, 300)
    assert summarizer.summarize_lines(lines, window_s=300) == expected, "positional vs keyword window_s"
    assert summarizer.summarize_fastlog(FASTLOG_FIXTURE) == expected, "default window_s must be 300"
    assert summarizer.summarize_fastlog(FASTLOG_FIXTURE, 300) == expected, "positional window_s on the file path"


def test_stdin_entry_point_is_byte_identical_to_the_file_entry_point() -> None:
    expected = summarizer.summarize_fastlog(FASTLOG_FIXTURE, window_s=300)
    saved_stdin = sys.stdin
    raw = open(FASTLOG_FIXTURE, "rb")
    sys.stdin = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
    try:
        assert summarizer.summarize_fastlog("-", window_s=300) == expected, "stdin must match the file path"
    finally:
        sys.stdin = saved_stdin
        raw.close()


def test_crlf_input_summarises_identically_to_lf() -> None:
    """A Windows checkout or a CRLF-mangled copy must not change the summary."""
    expected = summarizer.summarize_fastlog(FASTLOG_FIXTURE, window_s=300)
    with tempfile.TemporaryDirectory() as tmp:
        crlf = Path(tmp) / "fast.log"
        crlf.write_bytes(FASTLOG_FIXTURE.read_bytes().replace(b"\n", b"\r\n"))
        assert summarizer.summarize_fastlog(crlf, window_s=300) == expected, (
            "CRLF line endings changed the summary"
        )


# --------------------------------------------------------------------------- #
# 6. volume (generated in memory: no large log is committed)
# --------------------------------------------------------------------------- #


def test_a_large_log_is_compressed_quickly_and_exactly() -> None:
    count = 8000
    base = datetime(2025, 3, 26, 22, 3, 25)
    # `str.format` would eat the literal {TCP}; substitute a placeholder instead.
    template = (
        "__TS__  [**] [1:1000001:1] SQL Injection Attempt - time-based blind via SLEEP() [**] "
        "[Classification: Web Application Attack] [Priority: 1] {TCP} "
        "192.168.57.199:54228 -> 192.168.57.200:80"
    )
    lines = [
        template.replace(
            "__TS__", (base + timedelta(seconds=index)).strftime("%m/%d/%Y-%H:%M:%S") + ".000000"
        )
        for index in range(count)
    ]
    started = time.perf_counter()
    summary = summarizer.summarize_lines(lines, window_s=300)
    elapsed = time.perf_counter() - started
    assert episodes_in(summary) == 1, summary.splitlines()[0]
    assert alerts_in(summary) == count, summary.splitlines()[0]
    assert elapsed < 10.0, f"compressing {count} alerts took {elapsed:.2f}s"
    assert len(summary.splitlines()) <= 3, f"output must stay prompt-sized, got {len(summary.splitlines())} lines"


# --------------------------------------------------------------------------- #
# 7. dependency discipline
# --------------------------------------------------------------------------- #


def test_summarizer_imports_only_the_standard_library() -> None:
    tree = ast.parse(SUMMARIZER_PATH.read_text(encoding="utf-8"), filename=str(SUMMARIZER_PATH))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    externals = {name for name in imported if name not in sys.stdlib_module_names and name != "__future__"}
    assert not externals, f"ids/ must stay stdlib-only; found {sorted(externals)}"


# --------------------------------------------------------------------------- #
# 8. optional integration check against a real capture (opt-in, read-only)
# --------------------------------------------------------------------------- #


def test_real_captured_fastlog_if_configured() -> None:
    """Point ``SECLOOP_REAL_FASTLOG`` at a captured fast.log to run this."""
    configured = os.environ.get("SECLOOP_REAL_FASTLOG", "").strip()
    if not configured:
        _labkit.skip(
            "set SECLOOP_REAL_FASTLOG=<path to a real Suricata fast.log> to enable "
            "the real-capture integration check"
        )
    log_path = Path(configured)
    if not log_path.is_file():
        _labkit.skip(f"SECLOOP_REAL_FASTLOG is not a file: {log_path}")

    started = time.perf_counter()
    summary = summarizer.summarize_fastlog(log_path, window_s=300)
    elapsed = time.perf_counter() - started
    assert summary, f"real log {log_path} produced no summary"

    raw_lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    parsed = [line for line in raw_lines if summarizer.parse_fastlog_line(line) is not None]
    assert parsed, f"no alert in the supplied real log: {log_path}"
    assert alerts_in(summary) == len(parsed), (
        f"summary accounts for {alerts_in(summary)} of {len(parsed)} parsable alerts"
    )
    assert len(summary.splitlines()) <= 51, f"summary must stay prompt-sized: {len(summary.splitlines())} lines"
    print(
        f"    (integration) {log_path.name}: {len(raw_lines)} lines -> "
        f"{len(summary.splitlines())} summary lines in {elapsed:.2f}s"
    )


if __name__ == "__main__":
    raise SystemExit(run_module_tests(globals()))
