# SPDX-License-Identifier: Apache-2.0
"""Offline contract tests for ``battlefield/attacks/sqli_lab.py``.

No VM, no PHP, no MySQL, no Suricata, and **no network traffic**: the probe's
real ``main()`` is driven against a simulated lab transport and a simulated
monotonic clock, and a second set of tests runs the real CLI as a subprocess
against a *refused* target (which the probe rejects before opening a socket).

What is covered
---------------
* the ``[RESULT]`` line contract of ``docs/INTERFACES.md`` section 2: exactly one
  line on stdout, JSON parses, five stages in order with weights
  ``0.1/0.1/0.2/0.2/0.4``, ``score == sum(weight x success)`` as a JSON float;
* the full happy path (score ``1.0``) and the expected extractions for the lab
  schema: ``7 / secloop / secrets / secret_value / secloop-lab-fake-token-A1B2C3``;
* graceful degradation: unreachable target, oracle-not-confirmed (the
  ``block_ip`` case), and a refused non-lab target -- every path still emits a
  valid ``[RESULT]`` with ``score == 0.0`` and every stage ``false``;
* partial credit: 0.6 when stages 1-4 land but the final dump cannot;
* the lab-IP guard, including that a non-lab target costs zero requests;
* the shipped Suricata rules, by replaying the URIs this probe really generated
  through an offline matcher that implements ``content`` / ``nocase`` /
  ``distance`` / ``within`` the way Suricata does.

What is NOT covered
-------------------
``suricata -T`` (needs the target VM), MySQL's actual evaluation of the emitted
payloads, PHP behaviour, and real HTTP.

Run standalone (stdlib only) or with pytest::

    python tests/lab/test_sqli_probe.py
    python -m pytest tests/lab/test_sqli_probe.py -q
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _labkit  # noqa: E402  (path bootstrap must come first)
from _labkit import SQLI_LAB_PATH, SURICATA_RULES_PATH, run_module_tests  # noqa: E402

sqli = _labkit.load_sqli_lab()

# --------------------------------------------------------------------------- #
# The simulated lab
# --------------------------------------------------------------------------- #

#: What the lab schema really contains -- the answers a healthy target gives.
LAB_SCHEMA = {
    "db_name": "secloop",
    "table_name": "secrets",
    "column_name": "secret_value",
    "dump_row": "secloop-lab-fake-token-A1B2C3",
}

EXPECTED_STAGES = ["db_name_length", "db_name", "table_name", "column_name", "dump_row"]
EXPECTED_WEIGHTS = [0.1, 0.1, 0.2, 0.2, 0.4]

#: The RTC wraps the probe in `timeout ... 900`; a full run must fit inside it.
RTC_TIMEOUT_S = 900


class SimulatedClock:
    """Monotonic clock that only advances when the simulated transport is used.

    Any other ``time`` attribute is an assertion failure rather than a silent
    wrong measurement.
    """

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def __getattr__(self, item):  # pragma: no cover - guards harness misuse
        raise AssertionError(f"the probe unexpectedly used time.{item}")


class FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


class FakeSession:
    """A ``requests.Session`` stand-in that models the lab target's SQL.

    The transport understands exactly the condition grammar the probe emits, so
    a wrong payload shape surfaces as a failed stage rather than as a silently
    passing test.
    """

    def __init__(self, clock: SimulatedClock, *, reachable: bool, sleeps: bool, answers: dict) -> None:
        self.headers: dict[str, str] = {}
        self.time = clock
        self.reachable = reachable
        self.sleeps = sleeps
        self.answers = answers
        self.urls: list[str] = []
        self.requests = 0
        self.total_sleep = 0.0

    def close(self) -> None:
        pass

    # -- the fake database -------------------------------------------------- #

    def _expression_value(self, expression: str) -> str:
        if expression.startswith("database()"):
            return self.answers["db_name"]
        if "table_name FROM information_schema.tables" in expression:
            return self.answers["table_name"]
        if "column_name FROM information_schema.columns" in expression:
            return self.answers["column_name"]
        if "SELECT" in expression and "secrets" in expression:
            # An unknown column makes MySQL error out -> no rows -> an empty
            # extraction, which is exactly how a failed stage looks.
            return self.answers["dump_row"] if f"`{LAB_SCHEMA['column_name']}`" in expression else ""
        raise AssertionError(f"simulator does not recognise expression: {expression}")

    def _evaluate(self, condition: str) -> bool:
        condition = condition.strip()
        if condition == "1=1":
            return True
        if condition == "1=0":
            return False

        length = re.fullmatch(r"LENGTH\((?P<expr>.*)\)(?P<op>=|>)(?P<num>\d+)", condition, re.S)
        if length:
            actual = len(self._expression_value(length.group("expr")))
            wanted = int(length.group("num"))
            return actual == wanted if length.group("op") == "=" else actual > wanted

        code = re.fullmatch(
            r"ASCII\(SUBSTR\((?P<expr>.*),(?P<pos>\d+),1\)\)(?P<op>=|>)(?P<num>\d+)", condition, re.S
        )
        if code:
            text = self._expression_value(code.group("expr"))
            position = int(code.group("pos"))
            actual = ord(text[position - 1]) if position <= len(text) else 0
            wanted = int(code.group("num"))
            return actual == wanted if code.group("op") == "=" else actual > wanted

        char = re.fullmatch(r"SUBSTR\((?P<expr>.*),(?P<pos>\d+),1\)='(?P<char>.)'", condition, re.S)
        if char:
            text = self._expression_value(char.group("expr"))
            position = int(char.group("pos"))
            return position <= len(text) and text[position - 1] == char.group("char")

        raise AssertionError(f"simulator does not recognise condition: {condition}")

    # -- the transport ------------------------------------------------------ #

    def get(self, url: str, timeout=None, allow_redirects=None):
        self.requests += 1
        self.urls.append(url)
        self.time.now += 0.01  # one round trip
        if not self.reachable:
            raise OSError("simulated: connection refused")

        if Path(url.split("?")[0]).name == "index.php":
            return FakeResponse(200, "SecLoop target OK")

        # Model the server's view, not the wire: PHP's $_GET percent-decodes the
        # query value (and maps '+' to space).  Without this the simulator would
        # see `LENGTH(database())%3E16` and could never answer the probe.
        raw_id = urllib.parse.unquote_plus(url.split("?id=", 1)[1])
        condition = re.search(r"IF\((.*),SLEEP\(", raw_id, re.S)
        if condition and self.sleeps and self._evaluate(condition.group(1)):
            delay = float(re.search(r"SLEEP\(([0-9.]+)\)", raw_id).group(1))
            self.time.now += delay
            self.total_sleep += delay
        return FakeResponse(200, "SecLoop lab search\n1 | fake | fake\n")


def run_probe(argv: list[str], *, reachable: bool = True, sleeps: bool = True, answers: dict | None = None):
    """Run the probe's real ``main()`` over the simulated lab.

    Returns ``(exit_code, stdout, session)``.
    """
    clock = SimulatedClock()
    created: list[FakeSession] = []
    resolved_answers = dict(LAB_SCHEMA) if answers is None else dict(answers)

    class SessionFactory:
        def __call__(self):
            session = FakeSession(clock, reachable=reachable, sleeps=sleeps, answers=resolved_answers)
            created.append(session)
            return session

    class FakeRequests:
        Session = SessionFactory()

    original_requests, original_time = sqli.requests, sqli.time
    sqli.requests, sqli.time = FakeRequests(), clock
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            exit_code = sqli.main(argv)
    finally:
        sqli.requests, sqli.time = original_requests, original_time
    return exit_code, buffer.getvalue(), (created[0] if created else None)


def parse_result(stdout: str) -> dict:
    """Assert the stdout shape and return the decoded ``[RESULT]`` object."""
    lines = stdout.splitlines()
    assert len(lines) == 1, f"stdout must carry exactly one line, got {len(lines)}: {lines!r}"
    assert lines[0].startswith("[RESULT] "), f"missing '[RESULT] ' prefix: {lines[0][:60]!r}"
    return json.loads(lines[0][len("[RESULT] "):])


def run_cli(args: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess:
    """Run the real script as a subprocess (used only with socket-free targets)."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(
        [sys.executable, str(SQLI_LAB_PATH), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


# --------------------------------------------------------------------------- #
# Offline Suricata rule evaluation
# --------------------------------------------------------------------------- #


def split_keywords(rule: str) -> list[str]:
    """Split a rule body on ``;`` while ignoring semicolons inside strings."""
    parts: list[str] = []
    buffer: list[str] = []
    in_quote = escaped = False
    for char in rule:
        if in_quote:
            buffer.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = False
        elif char == '"':
            in_quote = True
            buffer.append(char)
        elif char == ";":
            parts.append("".join(buffer).strip())
            buffer = []
        else:
            buffer.append(char)
    parts.append("".join(buffer).strip())
    return [part for part in parts if part]


def load_rules() -> list[str]:
    """Return the non-comment lines of ``target/suricata/local.rules``."""
    assert SURICATA_RULES_PATH.is_file(), f"rules file missing: {SURICATA_RULES_PATH}"
    return [
        line.strip()
        for line in SURICATA_RULES_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def rule_matches(rule: str, uri: str) -> bool:
    """Approximate Suricata's evaluation of one rule against one request URI.

    Implements the parts that matter for these signatures: contents are matched
    in order, ``nocase`` lower-cases both sides, and ``distance``/``within`` are
    honoured relative to the previous match.  Suricata modifiers are separate
    ``;``-delimited keywords attached to the preceding ``content``.
    """
    contents: list[tuple[str, bool, int | None, int | None]] = []
    body = rule[rule.index("(") + 1: rule.rindex(")")]
    for keyword in split_keywords(body):
        if keyword.startswith("content:"):
            raw = keyword[len("content:"):].strip()
            text = raw[1:-1].replace('\\"', '"') if raw.startswith('"') else raw
            contents.append((text, False, None, None))
            continue
        if not contents:
            continue
        needle, nocase, distance, within = contents[-1]
        if keyword == "nocase":
            contents[-1] = (needle, True, distance, within)
        elif keyword.startswith("distance:"):
            contents[-1] = (needle, nocase, int(keyword.split(":", 1)[1]), within)
        elif keyword.startswith("within:"):
            contents[-1] = (needle, nocase, distance, int(keyword.split(":", 1)[1]))

    last_end = 0
    for needle, nocase, distance, within in contents:
        haystack = uri.lower() if nocase else uri
        target = needle.lower() if nocase else needle
        index = haystack.find(target, last_end + (distance or 0))
        if index < 0:
            return False
        if within is not None and index + len(target) > last_end + within:
            return False
        last_end = index + len(target)
    return True


# --------------------------------------------------------------------------- #
# 1. the [RESULT] contract, happy path
# --------------------------------------------------------------------------- #


def test_stdout_is_exactly_one_result_line() -> None:
    exit_code, stdout, _ = run_probe(["--target-ip", "192.168.57.200", "--delay", "2", "--log-level", "ERROR"])
    assert exit_code == 0, f"exit code {exit_code}"
    result = parse_result(stdout)
    assert result["attack_mode"] == "sqli", result["attack_mode"]
    assert result["target_ip"] == "192.168.57.200", result["target_ip"]
    # the human digest must never leak into the machine-readable line
    assert "stage " not in stdout and "score=" not in stdout, stdout


def test_stage_contract_matches_interfaces_2_3() -> None:
    _, stdout, _ = run_probe(["--target-ip", "192.168.57.200", "--delay", "2", "--log-level", "ERROR"])
    result = parse_result(stdout)
    stages = result["stages"]
    assert [stage["name"] for stage in stages] == EXPECTED_STAGES, [s["name"] for s in stages]
    assert [stage["weight"] for stage in stages] == EXPECTED_WEIGHTS, [s["weight"] for s in stages]
    assert all(stage["success"] is True for stage in stages), stages
    assert result["score"] == 1.0, result["score"]
    assert isinstance(result["score"], float), "score must be a JSON float, not an int"
    assert result["error"] is None, result["error"]
    assert result["oracle_errors"] == 0, result["oracle_errors"]


def test_happy_path_extracts_the_lab_schema() -> None:
    _, stdout, _ = run_probe(["--target-ip", "192.168.57.200", "--delay", "2", "--log-level", "ERROR"])
    extracted = parse_result(stdout)["extracted"]
    assert extracted == {
        "db_name_length": 7,
        "db_name": "secloop",
        "table_name": "secrets",
        "column_name": "secret_value",
        "dump_row": "secloop-lab-fake-token-A1B2C3",
    }, extracted


def test_score_equals_weighted_stage_sum() -> None:
    _, stdout, _ = run_probe(["--target-ip", "192.168.57.200", "--delay", "1", "--log-level", "ERROR"])
    result = parse_result(stdout)
    assert result["score"] == 1.0, (result["score"], result["stages"])
    assert result["score"] == round(sum(EXPECTED_WEIGHTS), 6), "all five stages must sum to exactly 1.0"
    # Compare against the paper's weights rather than re-deriving a sum from the very
    # `stages` the probe just emitted: that form is a restatement of the
    # implementation and would pass for any self-consistent (even wrong) score.
    assert [s["weight"] for s in result["stages"]] == list(EXPECTED_WEIGHTS), result["stages"]


def test_full_run_fits_the_rtc_timeout_budget() -> None:
    _, stdout, session = run_probe(["--target-ip", "192.168.57.200", "--delay", "2", "--log-level", "ERROR"])
    assert session is not None
    assert session.total_sleep < RTC_TIMEOUT_S, (
        f"a full-success run needs ~{session.total_sleep:.0f}s of SLEEP() budget, "
        f"which does not fit the {RTC_TIMEOUT_S}s timeout wrapper"
    )
    result = parse_result(stdout)
    assert result["requests"] == session.requests, (result["requests"], session.requests)
    assert result["requests"] > 100, f"a time-blind run should need many requests, got {result['requests']}"


def test_linear_mode_also_reaches_full_score() -> None:
    exit_code, stdout, _ = run_probe(
        ["--target-ip", "192.168.57.200", "--mode", "linear", "--delay", "1", "--log-level", "ERROR"]
    )
    assert exit_code == 0
    result = parse_result(stdout)
    assert result["score"] == 1.0, result["score"]
    assert result["mode"] == "linear", result["mode"]
    assert result["extracted"]["dump_row"] == LAB_SCHEMA["dump_row"], result["extracted"]


# --------------------------------------------------------------------------- #
# 2. graceful degradation
# --------------------------------------------------------------------------- #


def _assert_degraded(result: dict, token: str) -> None:
    assert result["score"] == 0.0, result["score"]
    assert isinstance(result["score"], float), "a failed run must report 0.0, not int 0"
    assert all(stage["success"] is False for stage in result["stages"]), result["stages"]
    assert result["error"], "a degraded run must set error"
    assert token in result["error"], f"{token!r} not in {result['error']!r}"


def test_unreachable_target_still_emits_a_valid_result() -> None:
    exit_code, stdout, _ = run_probe(
        ["--target-ip", "192.168.57.200", "--log-level", "ERROR"], reachable=False
    )
    assert exit_code == 0, "the exit status must stay 0 once [RESULT] is written"
    _assert_degraded(parse_result(stdout), "unreachable")


def test_blocked_oracle_still_emits_a_valid_result() -> None:
    """After ``block_ip`` the target may answer but SLEEP() never lands."""
    exit_code, stdout, _ = run_probe(
        ["--target-ip", "192.168.57.200", "--delay", "1", "--log-level", "ERROR"], sleeps=False
    )
    assert exit_code == 0
    _assert_degraded(parse_result(stdout), "oracle not confirmed")


def test_non_lab_target_is_refused_without_a_single_request() -> None:
    exit_code, stdout, session = run_probe(["--target-ip", "8.8.8.8", "--log-level", "ERROR"])
    assert exit_code == 0
    result = parse_result(stdout)
    _assert_degraded(result, "refusing to probe")
    assert result["requests"] == 0, result["requests"]
    # Either the probe refused before it built a session, or it built one and never
    # used it.  Written as an explicit branch: ``session is None or session.requests == 0``
    # would short-circuit away the check whenever the probe happened not to create a
    # session.
    if session is not None:
        assert session.requests == 0, "a refused target must not be contacted"


def test_loopback_dry_run_is_allowed() -> None:
    _, stdout, _ = run_probe(["--target-ip", "127.0.0.1", "--port", "8080", "--delay", "1", "--log-level", "ERROR"])
    result = parse_result(stdout)
    assert result["score"] == 1.0, result["score"]
    assert result["target_port"] == 8080, result["target_port"]


def test_partial_progress_is_honoured() -> None:
    """Stages 1-4 landing while stage 5 cannot dump must score exactly 0.6."""
    answers = dict(LAB_SCHEMA, column_name="no_such_column")
    _, stdout, _ = run_probe(
        ["--target-ip", "192.168.57.200", "--delay", "1", "--log-level", "ERROR"], answers=answers
    )
    result = parse_result(stdout)
    assert result["score"] == 0.6, result["score"]
    assert result["stages"][4]["success"] is False, result["stages"]
    assert all(stage["success"] for stage in result["stages"][:4]), result["stages"]
    assert result["error"] is None, "a stage-level failure is not a fatal error"


# --------------------------------------------------------------------------- #
# 3. the shipped Suricata rules detect this probe's traffic
# --------------------------------------------------------------------------- #


def test_rules_are_well_formed_and_in_the_local_sid_range() -> None:
    rules = load_rules()
    assert len(rules) >= _labkit.LOCAL_SID_MIN_RULES, (
        f"INTERFACES section 11 asks for at least {_labkit.LOCAL_SID_MIN_RULES} rules, "
        f"found {len(rules)}"
    )
    sids = []
    for rule in rules:
        assert rule.startswith("alert http any any -> any any ("), rule[:60]
        assert rule.endswith(";)"), rule[-40:]
        assert "flow:to_server,established" in rule, rule[:60]
        assert "http_uri" in rule, rule[:60]
        assert rule.count("msg:") == 1 and rule.count("sid:") == 1 and rule.count("rev:") == 1, rule[:60]
        assert ("distance:" in rule) == ("within:" in rule), f"distance/within must be paired: {rule[:60]}"
        # parentheses balance once quoted strings are removed
        stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', rule[rule.index("(") + 1: rule.rindex(")")])
        assert stripped.count("(") == stripped.count(")"), f"unbalanced syntax: {rule[:60]}"
        sids.append(int(re.search(r"sid:(\d+)", rule).group(1)))
    assert len(set(sids)) == len(sids), f"duplicate sid: {sids}"
    assert _labkit.is_consecutive_local_sids(sids), (
        f"expected sids {_labkit.LOCAL_SID_START}.."
        f"{_labkit.LOCAL_SID_START + len(sids) - 1} with no gaps, got {sorted(sids)}"
    )
    assert 'msg:"SQL Injection Attempt - ' in SURICATA_RULES_PATH.read_text(encoding="utf-8"), (
        "every msg must carry the summarizer's attack_type family prefix"
    )


def test_rules_fire_on_the_uris_the_probe_generated() -> None:
    _, _, session = run_probe(["--target-ip", "192.168.57.200", "--delay", "2", "--log-level", "ERROR"])
    assert session is not None and len(session.urls) > 100, "no traffic was recorded"

    fired: dict[int, int] = {}
    for uri in session.urls:
        for rule in load_rules():
            if rule_matches(rule, uri):
                sid = int(re.search(r"sid:(\d+)", rule).group(1))
                fired[sid] = fired.get(sid, 0) + 1

    assert len(fired) >= 4, f"only {sorted(fired)} of the rules detect the probe's own traffic"
    assert 1000001 in fired, "the SLEEP() rule must fire: time-blind injection is the marker"
    assert 1000007 in fired, "the literal-break-out + comment rule must fire"
    assert fired[1000001] > 100, fired[1000001]

    injected = [uri for uri in session.urls if "IF(" in uri]
    assert injected, "no injected URI recorded"
    assert all("%20" in uri for uri in injected), "payloads must be percent-encoded on the wire"
    # the break-out quote has to stay raw, or the string-literal rules cannot match
    assert all("'" in uri for uri in injected), "the SQL break-out quote must not be encoded"


def test_records_rules_from_the_family_the_summarizer_groups_on() -> None:
    """The probe and the summarizer must agree on the alert-family prefix."""
    summarizer = _labkit.load_summarizer()
    rules = load_rules()
    family = summarizer._signature_family(re.search(r'msg:"(.*?)";', rules[0]).group(1))
    assert family == "SQL Injection Attempt", family


# --------------------------------------------------------------------------- #
# 4. the real CLI, as a subprocess, with no sockets involved
# --------------------------------------------------------------------------- #


def test_cli_help_exits_zero_without_requests_or_network() -> None:
    proc = run_cli(["--help"])
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-400:])
    assert "usage:" in proc.stdout, proc.stdout[:200]
    # the epilog *mentions* the prefix, so assert no line actually is a result
    assert not any(line.startswith("[RESULT] ") for line in proc.stdout.splitlines()), (
        "--help must not emit a machine-readable result line"
    )


def test_cli_refusal_keeps_stdout_pure_and_logs_to_stderr() -> None:
    proc = run_cli(["--target-ip", "8.8.8.8"])
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-400:])
    result = parse_result(proc.stdout)  # asserts exactly one stdout line
    assert result["score"] == 0.0, result["score"]
    assert "refusing to probe" in str(result["error"]), result["error"]
    assert "refusing to probe" in proc.stderr, "the human digest belongs on stderr"


def test_cli_rejects_an_invalid_port_before_any_request() -> None:
    proc = run_cli(["--target-ip", "192.168.57.200", "--port", "0"])
    assert proc.returncode == 2, (proc.returncode, proc.stdout[:200])
    assert "[RESULT]" not in proc.stdout, "an argparse failure must not fabricate a result"
    assert "port" in proc.stderr.lower(), proc.stderr[-200:]


if __name__ == "__main__":
    raise SystemExit(run_module_tests(globals()))
