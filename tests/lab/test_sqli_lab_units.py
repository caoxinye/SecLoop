# SPDX-License-Identifier: Apache-2.0
"""Unit checks for the small pieces of ``battlefield/attacks/sqli_lab.py``.

These are the properties that are cheap to break and expensive to notice on a
VM: how a payload is encoded onto the wire, which hosts the probe refuses, and
the frozen shape of the five-stage contract.

What is covered
---------------
* payload encoding: SQL metacharacters the Suricata rules depend on
  (``'`` ``(`` ``)`` ``,`` ``=``) stay literal, while space/``#``/``&``/``+``/``;``
  become ``%20/%23/%26/%2B/%3B`` so they cannot be read as a URL fragment, a
  query separator or a ``+``-as-space. Encoding must also round-trip through
  ``urllib.parse.unquote`` unchanged, which is what makes it safe for PHP to
  decode the payload back into SQL;
* the lab-IP guard (``docs/INTERFACES.md`` section 1) with no override flag;
* the stage table: five names, fixed order, weights ``0.1/0.1/0.2/0.2/0.4``
  summing to ``1.0``, and the degraded-shape helpers agreeing with it;
* the blind payload shape and the timeout guard;
* dependency discipline: the attack script imports the standard library plus
  ``requests`` and nothing else (Kali rolling must not need extra packages).

What is NOT covered
-------------------
A live MySQL, PHP or Suricata.

Run standalone (stdlib only) or with pytest::

    python tests/lab/test_sqli_lab_units.py
    python -m pytest tests/lab/test_sqli_lab_units.py -q
"""

from __future__ import annotations

import ast
import re
import string
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _labkit  # noqa: E402  (path bootstrap must come first)
from _labkit import SQLI_LAB_PATH, run_module_tests  # noqa: E402

sqli = _labkit.load_sqli_lab()

#: ``urllib.parse.quote`` never encodes these (RFC 3986 unreserved).
ALWAYS_SAFE = set(string.ascii_letters + string.digits + "_.-~")


class _DummySession:
    """Stand-in for ``requests.Session``; the guarded helpers never use it."""

    def __init__(self) -> None:
        self.headers: dict[str, str] = {}


# --------------------------------------------------------------------------- #
# 1. payload encoding
# --------------------------------------------------------------------------- #


def test_sql_metacharacters_survive_encoding() -> None:
    greater = sqli._encode_payload("' AND IF(ASCII(SUBSTR(database(),1,1))>79,SLEEP(2),0)-- -")
    for token in ("'", "(", ")", ",", "SLEEP(", "ASCII(SUBSTR(", "--"):
        assert token in greater, f"{token!r} must stay literal for the Suricata rules: {greater}"
    assert "%20" in greater and " " not in greater, greater
    assert greater == "'%20AND%20IF(ASCII(SUBSTR(database(),1,1))%3E79,SLEEP(2),0)--%20-", greater

    # the equality form of the oracle: '=' is safe in a query value and must stay
    # literal, while '>' is escaped so it survives URL parsing
    equality = sqli._encode_payload("' AND IF(LENGTH(database())=7,SLEEP(2),0)-- -")
    assert "=" in equality and "%3D" not in equality, equality
    assert equality == "'%20AND%20IF(LENGTH(database())=7,SLEEP(2),0)--%20-", equality


def test_url_delimiters_are_encoded_exactly_once() -> None:
    cases = {
        "a b": "a%20b",
        "a#b": "a%23b",
        "a&b": "a%26b",
        "a+b": "a%2Bb",
        "a;b": "a%3Bb",
        "a>b": "a%3Eb",
        'a"b': "a%22b",
        "a\\b": "a%5Cb",
    }
    for payload, expected in cases.items():
        encoded = sqli._encode_payload(payload)
        assert encoded == expected, f"{payload!r} -> {encoded!r}, expected {expected!r}"


def test_encoding_round_trips_back_to_the_sql_the_server_will_see() -> None:
    payloads = [
        "' AND IF(1=1,SLEEP(2),0)-- -",
        "SUBSTR(x,1,1)='#'",
        "a#b&c+d;e%f",
        "LENGTH(database())>79",
        "quoted \"value\" and back\\slash",
        "SELECT `column` FROM `table` LIMIT 0,1",
    ]
    for payload in payloads:
        encoded = sqli._encode_payload(payload)
        assert urllib.parse.unquote(encoded) == payload, f"round trip broke for {payload!r}"


def test_no_character_escapes_the_safe_set_without_being_percent_encoded() -> None:
    encoded = sqli._encode_payload("odd chars: {}[]|^~`<>\"\\ \t\n#&+;=?%")
    stripped = encoded.replace("%20", "").replace("%09", "").replace("%0A", "")
    leftovers = set(re.sub(r"%[0-9A-Fa-f]{2}", "", stripped))
    unexpected = sorted(leftovers - ALWAYS_SAFE - set(sqli._URL_SAFE))
    assert not unexpected, f"unencoded characters escaped the safe set: {unexpected}"
    assert "%" not in re.sub(r"%[0-9A-Fa-f]{2}", "", encoded), (
        "every '%' must begin a valid percent-escape, or requests would double-encode"
    )


def test_safe_set_excludes_the_url_delimiters_that_would_truncate_a_payload() -> None:
    for dangerous in ("#", "&", "+", ";", "%", " ", '"', "?", "\\", "\t", "\n"):
        assert dangerous not in sqli._URL_SAFE, f"{dangerous!r} must never be in the safe set"


# --------------------------------------------------------------------------- #
# 2. the lab-IP guard
# --------------------------------------------------------------------------- #


def test_only_the_published_lab_network_and_loopback_are_allowed() -> None:
    cases = [
        ("192.168.57.200", True),   # the target (blue VM)
        ("192.168.57.199", True),   # the attacker (red VM)
        ("192.168.57.0", True),     # network address, still inside the range
        ("192.168.58.1", False),    # one octet away: refused
        ("192.168.56.1", False),    # VirtualBox's default host-only adapter lives
                                    # here, so targeting it would aim the probe at
                                    # the developer's host
        ("192.168.55.1", False),
        ("127.0.0.1", True),        # loopback, for a no-VM dry run only
        ("127.1.2.3", True),
        ("10.0.0.1", False),
        ("8.8.8.8", False),         # a real public host: refused
        ("::1", False),             # IPv6 loopback is not the lab
        ("not-an-ip", False),
        ("", False),
        ("192.168.57.200:80", False),
    ]
    mismatches = [
        f"{host!r} -> {sqli._allowed_target(host)} (expected {expected})"
        for host, expected in cases
        if sqli._allowed_target(host) is not expected
    ]
    assert not mismatches, "lab-IP guard mismatches: " + "; ".join(mismatches)


def test_allowed_networks_are_the_frozen_contract_values() -> None:
    assert tuple(sqli.ALLOWED_TARGET_NETS) == ("192.168.57.0/24", "127.0.0.0/8"), sqli.ALLOWED_TARGET_NETS
    assert sqli.DEFAULT_TARGET_IP == "192.168.57.200", sqli.DEFAULT_TARGET_IP


def test_the_cli_surface_is_exactly_what_the_contract_allows() -> None:
    """No flag may widen the target scope, and no flag may appear unannounced."""
    expected = {"--target-ip", "--port", "--mode", "--delay", "--timeout", "--log-level"}
    actual = option_strings()
    assert actual == expected, f"unexpected CLI surface: {sorted(actual)}"
    banned = {"--allow-any-target", "--allow-non-lab-target", "--force", "--any", "--unsafe", "--target"}
    assert not (banned & actual), f"a scope-widening flag appeared: {sorted(banned & actual)}"


def option_strings() -> set[str]:
    """Every long ``--option`` the probe's CLI advertises (static AST read)."""
    tree = ast.parse(SQLI_LAB_PATH.read_text(encoding="utf-8"), filename=str(SQLI_LAB_PATH))
    found: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("--"):
                    found.add(arg.value)
    return found


# --------------------------------------------------------------------------- #
# 3. the frozen five-stage contract
# --------------------------------------------------------------------------- #


def test_stage_table_is_frozen() -> None:
    assert [name for name, _ in sqli.STAGE_WEIGHTS] == [
        "db_name_length",
        "db_name",
        "table_name",
        "column_name",
        "dump_row",
    ], sqli.STAGE_WEIGHTS
    assert [weight for _, weight in sqli.STAGE_WEIGHTS] == [0.1, 0.1, 0.2, 0.2, 0.4], sqli.STAGE_WEIGHTS
    assert sum(weight for _, weight in sqli.STAGE_WEIGHTS) == 1.0
    assert sqli.ATTACK_MODE == "sqli", sqli.ATTACK_MODE
    assert sqli.RESULT_PREFIX == "[RESULT] ", repr(sqli.RESULT_PREFIX)
    assert sqli.HEALTH_MARKER == "SecLoop target OK", sqli.HEALTH_MARKER


def test_degraded_helpers_agree_with_the_stage_table() -> None:
    stages = sqli._blank_stages()
    assert [stage["name"] for stage in stages] == [name for name, _ in sqli.STAGE_WEIGHTS]
    assert all(stage["success"] is False for stage in stages), stages
    assert sqli._blank_extracted() == {name: None for name, _ in sqli.STAGE_WEIGHTS}


def test_blind_payload_shape() -> None:
    probe = sqli.SqliLabProbe("192.168.57.200", 80, 2.0, 12.0, "binary", _DummySession())
    suffix = probe._blind_suffix("1=1")
    assert suffix.startswith("' AND IF("), suffix
    assert "SLEEP(2)" in suffix, suffix
    assert suffix.endswith("-- -"), suffix
    assert probe._url("") == "http://192.168.57.200:80/search.php?id=1", probe._url("")
    assert "%20" in probe._url(suffix), probe._url(suffix)


def test_sql_number_and_identifier_quoting() -> None:
    assert sqli._sql_number(2.0) == "2", sqli._sql_number(2.0)
    assert sqli._sql_number(0.5) == "0.5", sqli._sql_number(0.5)
    assert sqli._quote_identifier("secret_value") == "`secret_value`"
    assert sqli._quote_identifier("we`ird") == "`we``ird`", "backticks must be doubled, not dropped"


def test_timeout_guard_always_outlasts_the_sleep() -> None:
    assert sqli._effective_timeout(2.0, 12.0) == 12.0
    assert sqli._effective_timeout(5.0, 3.0) == 12.0, "a too-small timeout must be raised, not honoured"
    assert sqli._effective_timeout(0.5, 8.0) == 8.0


# --------------------------------------------------------------------------- #
# 4. dependency discipline
# --------------------------------------------------------------------------- #


def test_attack_script_imports_stdlib_plus_requests_only() -> None:
    tree = ast.parse(SQLI_LAB_PATH.read_text(encoding="utf-8"), filename=str(SQLI_LAB_PATH))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    externals = {
        name
        for name in imported
        if name not in sys.stdlib_module_names and name not in {"requests", "__future__"}
    }
    assert not externals, (
        f"the Kali probe may only use the stdlib plus requests; found {sorted(externals)}"
    )
    assert "requests" in imported, "the probe is expected to depend on requests"


def test_requests_import_is_guarded_so_the_cli_still_starts_without_it() -> None:
    source = SQLI_LAB_PATH.read_text(encoding="utf-8")
    assert "try:" in source and "except ImportError" in source, (
        "a missing requests must not prevent --help or a degradable [RESULT]"
    )
    assert "requests is not installed" in source or "not installed" in source, (
        "the missing-dependency path must explain itself"
    )


if __name__ == "__main__":
    raise SystemExit(run_module_tests(globals()))
