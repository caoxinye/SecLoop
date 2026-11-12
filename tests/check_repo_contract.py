#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Repository contract checker for SecLoop.

Verifies the repo-wide invariants listed in docs/INTERFACES.md section 12.
Deliberately dependency-free (stdlib only) so it runs anywhere.

Usage:
    python tests/check_repo_contract.py [--root <path>] [--quiet]

Exit code is 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".vagrant", ".pytest_cache", ".idea", ".vscode", "node_modules"}

# Credential-shaped patterns. Checked in EVERY text file, docs included: a real
# key is a real key no matter which file it lands in.  The prefixes below are
# standard, publicly documented formats, so they are written literally.
SECRET_PATTERNS = [
    (r"sk-or-v1-[A-Za-z0-9]", "cloud-LLM API key"),
    (r"\bsk-[A-Za-z0-9]{20,}", "generic sk- API key"),
    (r"hf_[A-Za-z0-9]{20,}", "model-hub token"),
    (r"WANDB_API_KEY\s*=\s*['\"]?[A-Za-z0-9]{20,}", "hardcoded experiment-tracker key"),
    (r"BEGIN RSA PRIVATE KEY", "private key material"),
    (r"BEGIN OPENSSH PRIVATE KEY", "private key material"),
]

# Identifying strings that must not appear in CODE or CONFIG.  Markdown docs are
# exempt from the *scan* because the contract and security policy legitimately
# discuss them in the abstract -- but they are assembled from fragments here, on
# purpose: this file is published, and a list of "strings you must not leak" is
# itself a disclosure if it spells those strings out.  Keep the fragments.
_FRAG = {
    "vendor": "open" + "router",
    "private_host": "lin" + "jhs" + r"\.top",
    "internal_net": "10" + r"\." + "122" + r"\.",
    "personal_id": "u2022" + "211603",
    "dead_endpoint": "soar" + r"\." + "lin" + "jhs",
    "private_mirror": "gitee" + r"\.com/" + "lin" + "jhs",
}

HYGIENE_PATTERNS = [
    (_FRAG["vendor"], "cloud vendor name"),
    (_FRAG["private_host"], "private host domain"),
    (_FRAG["internal_net"], "internal network address"),
    (_FRAG["personal_id"], "personal identifier (student id)"),
    (_FRAG["dead_endpoint"], "dead internal endpoint"),
    (_FRAG["private_mirror"], "private mirror reference"),
]

DOC_SUFFIXES = {".md", ".cff"}

# Text-ish files worth scanning; binaries are skipped.
TEXT_SUFFIXES = {".py", ".sh", ".yaml", ".yml", ".json", ".md", ".txt", ".cfg", ".toml", ".cff", ".rules", ".php", ".sql", ".j2", ".ini", ".env", ".rst", ".in", ""}

SPDX = "SPDX-License-Identifier: Apache-2.0"


class Report:
    def __init__(self, quiet: bool = False) -> None:
        self.failures: list[str] = []
        self.warnings: list[str] = []
        self.passes: list[str] = []
        self.quiet = quiet

    def ok(self, msg: str) -> None:
        self.passes.append(msg)
        if not self.quiet:
            print(f"  PASS  {msg}")

    def fail(self, msg: str) -> None:
        self.failures.append(msg)
        print(f"  FAIL  {msg}")

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        if not self.quiet:
            print(f"  WARN  {msg}")

    def section(self, title: str) -> None:
        if not self.quiet:
            print(f"\n=== {title} ===")


def iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        yield p


RE_CALL_ATTRS = {"search", "match", "fullmatch", "findall", "finditer", "compile", "sub", "split"}


def regex_literals(path: Path) -> list[str]:
    """Return the string literals actually passed to ``re.<method>(...)``.

    Scanning raw file text for a pattern like ``Score:`` produces false
    positives, because docstrings and comments legitimately *describe* a
    legacy contract the code does not act on.  Only real regex literals matter, so we
    pull them out of the AST instead.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_re_call = (
            isinstance(func, ast.Attribute)
            and func.attr in RE_CALL_ATTRS
            and isinstance(func.value, ast.Name)
            and func.value.id == "re"
        ) or (
            isinstance(func, ast.Attribute)
            and func.attr in RE_CALL_ATTRS
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "re"
        )
        if not is_re_call or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            out.append(first.value)
    return out


def strip_yaml_noise(line: str) -> str:
    """Drop a trailing ``# comment`` and surrounding quotes from a YAML scalar."""
    # remove an unquoted trailing comment
    in_single = in_double = False
    cut = len(line)
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            cut = i
            break
    return line[:cut].strip().strip("'\"")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    rep = Report(args.quiet)
    print(f"SecLoop contract check\nroot: {root}\n")

    files = list(iter_files(root))
    py_files = [p for p in files if p.suffix == ".py"]
    print(f"scanned {len(files)} files ({len(py_files)} .py)")

    # --- 1. every Python file must parse -------
    rep.section("1. ast.parse over every .py")
    if not py_files:
        rep.warn("no .py files found yet")
    bad = []
    for p in py_files:
        try:
            ast.parse(p.read_text(encoding="utf-8", errors="replace"), filename=str(p))
        except SyntaxError as e:
            bad.append(f"{p.relative_to(root)}:{e.lineno}: {e.msg}")
    if bad:
        for b in bad:
            rep.fail(f"SyntaxError: {b}")
    elif py_files:
        rep.ok(f"all {len(py_files)} .py files parse cleanly")

    # --- 2. SPDX headers ----------------------------------------------------
    rep.section("2. SPDX license headers on .py files")
    missing = [str(p.relative_to(root)) for p in py_files if SPDX not in p.read_text(encoding="utf-8", errors="replace")]
    if missing:
        rep.fail(f"{len(missing)} .py file(s) missing '{SPDX}': {', '.join(missing[:5])}"
                 + (" ..." if len(missing) > 5 else ""))
    elif py_files:
        rep.ok("all .py files carry the SPDX header")

    # --- 3. secrets / internal endpoints -----------------------------------
    rep.section("3. no secrets, cloud vendor names or internal endpoints")
    hits = []
    for p in files:
        if p.suffix not in TEXT_SUFFIXES:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rules = list(SECRET_PATTERNS)
        if p.suffix not in DOC_SUFFIXES:
            rules += HYGIENE_PATTERNS
        for pat, label in rules:
            for m in re.finditer(pat, text, re.IGNORECASE):
                line = text[: m.start()].count("\n") + 1
                hits.append(f"{p.relative_to(root)}:{line}: {label}")
    # the checker itself contains the patterns; ignore self
    hits = [h for h in hits if "check_repo_contract.py" not in h]
    if hits:
        for h in hits[:15]:
            rep.fail(h)
        if len(hits) > 15:
            rep.fail(f"... {len(hits) - 15} more")
    else:
        rep.ok("clean")

    # --- 4. no bytecode / no vendored trl ----------------------------------
    rep.section("4. tree hygiene: no bytecode, no stray caches, LF endings, no vendored TRL")
    # NOTE: this walk must NOT use iter_files(), which deliberately skips
    # __pycache__: reusing it would be structurally blind to the very thing it
    # claims to verify, reporting "no .pyc present" while .pyc files sit on disk.
    # Walk the tree unfiltered instead.
    #
    # Machine-local, gitignored trees ARE excluded: a virtualenv and a VMware
    # `.vagrant/` directory are full of bytecode by construction and are not part
    # of the deliverable.  Note that `__pycache__` deliberately stays in scope --
    # that is the thing being hunted.
    MACHINE_LOCAL = {".venv", "venv", ".vagrant", ".git", ".pytest_cache", "node_modules"}
    bytecode = sorted(
        p for p in root.rglob("*")
        if not any(part in MACHINE_LOCAL for part in p.relative_to(root).parts)
        and (p.name == "__pycache__" or p.suffix in (".pyc", ".pyo"))
    )
    if bytecode:
        for p in bytecode[:8]:
            rep.fail(f"bytecode present: {p.relative_to(root)}")
        if len(bytecode) > 8:
            rep.fail(f"... and {len(bytecode) - 8} more bytecode entries")
    else:
        rep.ok("no __pycache__ directories and no .pyc/.pyo files")

    # `.pytest_cache` is machine-local, so the bytecode walk above skips it -- but
    # `pytest.ini` states the tree must not carry one either.  Check it explicitly
    # here, because a stale `.pytest_cache/v/cache/lastfailed` would otherwise ship a
    # "these 10 tests failed" record and make an all-green suite look retro-fitted.
    stray_caches = sorted(
        p for p in root.rglob(".pytest_cache")
        if p.is_dir()
        and not any(part in {".venv", "venv", ".vagrant"} for part in p.relative_to(root).parts)
    )
    if stray_caches:
        for p in stray_caches:
            rep.fail(f"stray .pytest_cache in the tree: {p.relative_to(root)} (pytest.ini forbids it)")
    else:
        rep.ok("no stray .pytest_cache directories")

    # Line-ending / encoding hygiene (docs/INTERFACES.md §0).  These checks live in the
    # gate rather than in a separate script: without them it can report "all blocking
    # checks passed" while files have no final newline at all.
    crlf: list[str] = []
    lone_cr: list[str] = []
    bom: list[str] = []
    no_final_newline: list[str] = []
    for p in iter_files(root):
        if p.suffix not in TEXT_SUFFIXES:
            continue
        try:
            raw = p.read_bytes()
        except OSError:  # pragma: no cover - unreadable file, reported elsewhere
            continue
        if not raw:
            continue
        rel = str(p.relative_to(root))
        if raw.startswith(b"\xef\xbb\xbf"):
            bom.append(rel)
        if b"\r\n" in raw:
            crlf.append(rel)
        elif b"\r" in raw:
            lone_cr.append(rel)
        if not raw.endswith(b"\n"):
            no_final_newline.append(rel)

    for label, found in (
        ("CRLF line endings", crlf),
        ("lone CR line endings", lone_cr),
        ("UTF-8 BOM", bom),
        ("missing final newline", no_final_newline),
    ):
        if found:
            for rel in found[:8]:
                rep.fail(f"{label}: {rel}")
            if len(found) > 8:
                rep.fail(f"... and {len(found) - 8} more with {label}")
        else:
            rep.ok(f"no {label}")

    vendored = (root / "trl" / "__init__.py").exists() or any(
        p.name == "grpo_trainer.py" and "trl" in p.parts for p in py_files
    )
    if vendored:
        rep.fail("vendored TRL detected (it must stay an upstream pin)")
    else:
        rep.ok("TRL not vendored")

    for gone in ("training/src/rloo", "agent/rag"):
        if (root / gone).exists():
            rep.fail(f"{gone}/ should not exist")
        else:
            rep.ok(f"{gone}/ absent")

    # --- 5. recipe carries the five SA-GRPO keys ---------------------------
    rep.section("5. recipe YAML declares the SA-GRPO knobs explicitly")

    def yaml_scalar(text: str, key: str) -> str | None:
        m = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.*)$", text, re.M)
        return None if m is None else strip_yaml_noise(m.group(1))

    def as_float(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    keys = ("num_generations", "scale_rewards", "beta", "epsilon", "epsilon_high", "loss_type")
    recipes = list((root / "training" / "recipes").rglob("config.yaml")) if (root / "training" / "recipes").exists() else []
    if not recipes:
        rep.warn("no recipe config.yaml found yet")
    for r in recipes:
        text = r.read_text(encoding="utf-8", errors="replace")
        vals = {k: yaml_scalar(text, k) for k in keys}
        missing_keys = [k for k, v in vals.items() if v is None]
        rel = r.relative_to(root)
        if missing_keys:
            rep.fail(f"{rel}: missing {missing_keys}")
        else:
            rep.ok(f"{rel}: all six keys present")
        expected = {
            "num_generations": "7",
            "scale_rewards": "false",
            "beta": "0.0",
            "epsilon": "0.2",
            "epsilon_high": "0.28",
            "loss_type": "dr_grpo",
        }
        mismatched: list[str] = []
        for k, want in expected.items():
            got = vals.get(k)
            if got is None:
                continue
            same = (
                as_float(got) == as_float(want)
                if as_float(want) is not None
                else got.strip().lower() == want
            )
            if not same:
                mismatched.append(f"{k}={got!r} (paper: {want})")
                rep.warn(f"{rel}: {k} is {got!r}, paper Table IV/§10.1 says {want}")
        # Only claim a match once every value was actually compared AND agreed.  Printing
        # "values match the paper" whenever the keys merely *existed* would let e.g.
        # `num_generations: 5` produce a PASS line plus a warning, and a reader skimming
        # the PASS lines would conclude the contract held.  A disagreement is a blocking
        # failure, not a warning.
        if missing_keys:
            pass  # already reported above
        elif mismatched:
            rep.fail(f"{rel}: SA-GRPO values disagree with the paper: {'; '.join(mismatched)}")
        else:
            rep.ok(f"{rel}: all six SA-GRPO values match the paper")

    # --- 5b. the SA-GRPO change count is stated the same way everywhere ----
    # Every document states the count as "five algorithm values".  Two different counts
    # in two documents leave a reader unable to tell where the algorithm's definition
    # boundary is -- and the one value most easily missed (`loss_type`) is the one the
    # validator hard-fails on.
    stale_counts = {
        "README.md": ("three changes", "four changes"),
        "README.zh-CN.md": ("三个改动", "四个改动"),
        "NOTICE": ("four configuration values", "three configuration values"),
        "docs/architecture.md": ("the four SA-GRPO", "the three SA-GRPO"),
        "docs/INTERFACES.md": ("4 个值", "3 个值"),
        "docs/reproduction.md": ("four knobs", "three knobs"),
        "requirements/README.md": ("four configuration values", "three configuration values"),
        "training/recipes/Qwen2.5-7B-Instruct/grpo/config.yaml": (
            "four algorithm values",
            "three algorithm values",
        ),
    }
    offenders: list[str] = []
    for rel, phrases in stale_counts.items():
        path = root / rel
        if not path.exists():
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        offenders += [f"{rel}: {phrase!r}" for phrase in phrases if phrase in body]

    # The list above is a blacklist of phrasings, so a *new* file saying "four knobs" would
    # slip through it.  This sweep is the catch-all.
    # It deliberately requires a *definition* verb nearby: "the four knobs that define
    # SA-GRPO" is wrong, while "理由与其余四个值相同" (the other four of five) is right.
    stale_count_res = (
        re.compile(
            r"\b(?:two|three|four)\s+(?:knobs|changes|values|settings|parameters)\b"
            r"[^.\n]{0,40}?\b(?:define|defines|defining)\b",
            re.IGNORECASE,
        ),
        re.compile(r"(?:两|三|四)个(?:值|改动|配置)[^。\n]{0,20}?(?:定义|构成|决定)"),
    )
    for path in sorted(root.rglob("*.md")):
        if any(part in {".venv", ".vagrant", "__pycache__", ".git"} for part in path.parts):
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        for pattern in stale_count_res:
            for match in pattern.finditer(body):
                line = body[: match.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(root)}:{line}: {match.group(0)!r}")

    if offenders:
        for offender in offenders:
            rep.fail(f"stale SA-GRPO change count: {offender}")
    else:
        rep.ok("every document states the SA-GRPO change count consistently (five values)")

    # --- 6. attack result contract: producer and consumer agree ------------
    rep.section("6. '[RESULT]' JSON contract used on both sides")
    producer_files = [p for p in py_files if p.name.startswith("sqli_lab")]
    consumer_files = [p for p in py_files if p.name == "red_team_controller.py"]
    for p in producer_files:
        t = p.read_text(encoding="utf-8", errors="replace")
        (rep.ok if "[RESULT]" in t else rep.fail)(f"{p.relative_to(root)} emits [RESULT]")
    for p in consumer_files:
        t = p.read_text(encoding="utf-8", errors="replace")
        rel = p.relative_to(root)
        (rep.ok if "[RESULT]" in t else rep.fail)(f"{rel} parses [RESULT]")
        legacy = [lit for lit in regex_literals(p) if re.search(r"[Ss]core\s*:", lit)]
        if legacy:
            rep.fail(f"{rel} compiles legacy score regexes: {legacy[:3]}")
        else:
            rep.ok(f"{rel}: no legacy score regex literals")
    if not producer_files or not consumer_files:
        rep.warn("producer/consumer pair not both present yet")

    # --- 7. PEV must not invert (measurement vs polarity) -----------------
    rep.section("7. PEV reports raw rs_attack (no inversion)")
    pev = root / "battlefield" / "soc" / "policy_execution_validator.py"
    if not pev.exists():
        rep.warn("policy_execution_validator.py not present yet")
    else:
        t = pev.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(t)
        except SyntaxError:
            tree = None
        fn = None
        if tree is not None:
            fn = next(
                (n for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == "compute_rs_attack"),
                None,
            )
        if fn is None:
            rep.fail("PEV has no compute_rs_attack() function")
        else:
            body = "\n".join(t.splitlines()[fn.lineno - 1: fn.end_lineno])
            inversion = re.findall(r"\b1(?:\.0)?\s*-", body)
            if inversion:
                rep.fail(f"PEV compute_rs_attack() applies an inversion {inversion} "
                         f"(must return the raw Eq.11 measurement)")
            else:
                rep.ok("PEV compute_rs_attack() returns the raw measurement (no inversion)")
        if "defense_effectiveness" not in t:
            rep.warn("PEV does not expose defense_effectiveness convenience field")
        else:
            rep.ok("PEV exposes defense_effectiveness separately")

    # --- 8. reward layer owns the polarity (Eq.20 semantics) --------------
    rep.section("8. reward layer owns the polarity (R_eva from rs_attack, not gated on rs_service)")
    rewards = root / "training" / "src" / "open_r1" / "rewards.py"
    if not rewards.exists():
        rep.warn("training rewards.py not present yet")
    else:
        t = rewards.read_text(encoding="utf-8", errors="replace")

        # Eq.20 is `R_eva = W_BATTLE-FIELD` ("absence of alarms"); the estimator
        # `1 - rs_attack` is this repository's.  Both properties are read off the AST of
        # the `r_eva` assignment, never off the raw text -- the docstring quotes the
        # formula, so a text search would be satisfied by prose alone.
        try:
            tree = ast.parse(t)
        except SyntaxError as exc:
            rep.fail(f"rewards.py does not parse: {exc}")
        else:
            r_eva_assignments = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "r_eva"
                    for target in node.targets
                )
            ]
            if not r_eva_assignments:
                rep.fail("rewards.py never assigns r_eva")
            else:
                def _names(node):
                    return {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}

                derived = [n.lineno for n in r_eva_assignments if "rs_attack" in _names(n)]
                # `r_eva = 0.0` before the SOC round trip is the unmeasured default, not a
                # rival definition; anything else that does not use rs_attack would be.
                suspicious = [
                    n.lineno
                    for n in r_eva_assignments
                    if n.lineno not in derived and not isinstance(n.value, ast.Constant)
                ]
                if not derived:
                    rep.fail(
                        "no `r_eva` assignment derives from rs_attack; the Eq.20 polarity "
                        "must come from the measurement (prose does not count)"
                    )
                elif suspicious:
                    rep.fail(
                        f"r_eva is assigned from something other than rs_attack at line(s) "
                        f"{suspicious}, and it is not a constant default"
                    )
                else:
                    rep.ok(
                        f"R_eva derives from rs_attack (AST, line(s) {derived}); the other "
                        f"assignment(s) are constant defaults"
                    )
                # The *shape* is checked, not the name: a check for the identifier
                # `rs_service` would be evaded by `(1 - rs_attack) * service_gate`, so
                # renaming the gate must not let the gate back in.
                # So `r_eva` must be *exactly* `1 - <one reference>`: no multiplication,
                # no conditional, no extra term, whatever anything is called.
                badly_shaped = [
                    node.lineno
                    for node in r_eva_assignments
                    if node.lineno in derived
                    and not (
                        isinstance(node.value, ast.BinOp)
                        and isinstance(node.value.op, ast.Sub)
                        and isinstance(node.value.left, ast.Constant)
                        and node.value.left.value == 1
                        and isinstance(node.value.right, (ast.Name, ast.Attribute))
                    )
                ]
                if badly_shaped:
                    rep.fail(
                        f"R_eva at line(s) {badly_shaped} is not exactly `1 - <measurement>`; "
                        "Eq.20's 'absence of alarms' earns the point with no further condition. "
                        "Any extra factor or conditional -- under any variable "
                        "name -- puts the gate back."
                    )
                else:
                    rep.ok(
                        "R_eva is exactly `1 - <measurement>` (AST shape, independent of names)"
                    )

    # --- 9. prompt carries all three sections -----------------------------
    rep.section("9. prompt contains C / T_A / E in both paths (Eq.4)")
    for rel in ("agent/llm/llm_interface.py", "training/src/open_r1/grpo.py"):
        p = root / rel
        if not p.exists():
            rep.warn(f"{rel} not present yet")
            continue
        t = p.read_text(encoding="utf-8", errors="replace")
        # Read the *prompt-building functions*, not the file: a whole-file regex for
        # "alert" is satisfied by any docstring or unrelated log line in an 900-line
        # module.  Only names, attributes and keyword arguments count
        # -- comments and docstrings are not AST nodes of those kinds.
        try:
            tree = ast.parse(t)
        except SyntaxError as exc:
            rep.fail(f"{rel}: does not parse ({exc})")
            continue
        builders = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and re.search(r"prompt|message", node.name, re.IGNORECASE)
        ]
        if not builders:
            rep.fail(f"{rel}: no prompt/message builder function found")
            continue
        tokens: set[str] = set()
        for builder in builders:
            for argument in builder.args.args + builder.args.kwonlyargs:
                tokens.add(argument.arg)
            for node in ast.walk(builder):
                if isinstance(node, ast.Name):
                    tokens.add(node.id)
                elif isinstance(node, ast.Attribute):
                    tokens.add(node.attr)
                elif isinstance(node, ast.keyword) and node.arg:
                    tokens.add(node.arg)
        joined = " ".join(sorted(tokens))
        has_alerts = bool(re.search(r"alert|summary", joined, re.IGNORECASE))
        has_tools = bool(
            re.search(
                r"tool_descriptions|get_tool_descriptions|environment_tools|available_tools",
                joined,
                re.IGNORECASE,
            )
        )
        has_env = bool(re.search(r"environment|platform", joined, re.IGNORECASE))
        if has_env and has_tools and has_alerts:
            rep.ok(
                f"{rel}: C/T_A/E present in the builder code of "
                f"{[b.name for b in builders]}"
            )
        else:
            rep.fail(
                f"{rel}: prompt builder(s) {[b.name for b in builders]} missing a section "
                f"(env={has_env}, tools={has_tools}, alerts={has_alerts})"
            )

    # --- 10. expected top-level files -------------------------------------
    rep.section("10. required top-level files")
    for name in ("README.md", "LICENSE", "NOTICE", "SECURITY.md", "CITATION.cff", ".gitignore",
                 "docs/INTERFACES.md", "docs/architecture.md", "docs/quickstart.md"):
        (rep.ok if (root / name).exists() else rep.fail)(f"{name} present")

    # --- 11. documented API surfaces match the code ------------------------
    rep.section("11. the documented /health body matches what the server returns")
    server = root / "battlefield" / "soc_server.py"
    if not server.exists():
        rep.warn("battlefield/soc_server.py not present yet")
    else:
        text = server.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            rep.fail(f"soc_server.py does not parse: {exc}")
        else:
            served: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == "health":
                    for inner in ast.walk(node):
                        if isinstance(inner, ast.Dict):
                            served |= {
                                k.value
                                for k in inner.keys
                                if isinstance(k, ast.Constant) and isinstance(k.value, str)
                            }
            if not served:
                rep.warn("could not find the /health response dict")
            else:
                # The module docstring is what a client written against the "frozen
                # contract" reads, so a key the handler returns and the docstring never
                # mentions is a contract break.  Keys only have to be *mentioned*; the
                # point is that adding one cannot silently skip the documentation.
                undocumented = sorted(k for k in served if f'"{k}"' not in text.split('"""')[1])
                if undocumented:
                    rep.fail(
                        f"soc_server.py /health returns {undocumented} without documenting "
                        f"them in the module docstring"
                    )
                else:
                    rep.ok(f"all {len(served)} /health keys appear in the module docstring")

    # --- 12. one tool table, and availability discovered from the environment --
    rep.section("12. one tool table; availability discovered, never assumed")
    catalogue = root / "battlefield" / "soc" / "tool_catalogue.py"
    probe = root / "battlefield" / "soc" / "capability_probe.py"
    btc = root / "battlefield" / "soc" / "blue_team_controller.py"
    agent_registry = root / "agent" / "tools" / "security_tools.py"
    config = root / "agent" / "config.json"
    server = root / "battlefield" / "soc_server.py"

    def module_binds(tree, name):
        """True when the module assigns/annotates ``name`` at module level."""
        for node in getattr(tree, "body", ()):
            if isinstance(node, ast.Assign):
                if any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                    return True
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.target.id == name:
                    return True
        return False

    def parsed(path):
        """Parse a module, or return ``None`` (the missing-file case)."""
        if not path.exists():
            return None
        return ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))

    def dataclass_fields(tree, class_name):
        """Field names annotated on a dataclass, by AST — prose cannot satisfy this."""
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for statement in node.body:
                    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                        names.add(statement.target.id)
        return names

    def function(tree, name):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return node
        return None

    def defines(tree, name):
        """True when ``name`` is bound at module level as a variable, function or class.

        ``module_binds`` only sees assignments, so a check written with it silently cannot
        see a function or a class -- and a check that cannot see what it asserts on is worse
        than no check, because it reports PASS.
        """
        if module_binds(tree, name):
            return True
        for node in getattr(tree, "body", ()):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == name:
                    return True
        return False

    def parameter_names(node):
        args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        return {argument.arg for argument in args}

    def calls_named(node):
        """Names of functions actually *called* within ``node`` (module or function)."""
        called = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                func = sub.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
                elif isinstance(func, ast.Attribute):
                    called.add(func.attr)
        return called

    def route_paths(tree):
        """``@app.route("…")`` string literals — a comment cannot satisfy this."""
        paths = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                for argument in decorator.args:
                    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                        paths.add(argument.value)
        return paths

    tree = parsed(catalogue)
    if tree is None:
        rep.fail("battlefield/soc/tool_catalogue.py is missing; there is no single table")
    else:
        (rep.ok if module_binds(tree, "TOOL_CATALOGUE") else rep.fail)(
            "the catalogue defines TOOL_CATALOGUE"
        )

        # Availability must be declared as *requirements to detect*, not as a per-OS list:
        # a table cannot know what a particular machine has installed. Checked on the
        # dataclass itself, because the same words appear in the module docstring.
        fields = dataclass_fields(tree, "ToolSpec")
        for needed in ("requires_any", "requires_root", "renderer", "privileged", "template"):
            (rep.ok if needed in fields else rep.fail)(
                f"the ToolSpec dataclass declares the {needed} field"
            )
        if "platforms" in fields:
            rep.fail(
                "the catalogue hard-codes a per-OS tool list (`platforms` field); "
                "T_A is defined by the environment (paper Eq.3), so it must be probed"
            )
        else:
            rep.ok("the catalogue declares no per-OS tool field")

    tree = parsed(probe)
    if tree is None:
        rep.fail("battlefield/soc/capability_probe.py is missing; T_A would have to be assumed")
    else:
        defined = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        for needed in ("parse_probe_output", "probe_capabilities", "CapabilityProbeError"):
            (rep.ok if needed in defined else rep.fail)(f"the probe defines {needed}")

    tree = parsed(btc)
    if tree is None:
        rep.fail("battlefield/soc/blue_team_controller.py is missing")
    else:
        text = btc.read_text(encoding="utf-8", errors="replace")
        if "_TOOL_SPECS" in text:
            rep.fail("blue_team_controller.py holds a private tool table (_TOOL_SPECS)")
        else:
            rep.ok("blue_team_controller.py has no private tool table")
        # A *call*, not the identifier appearing in an import or a docstring.
        capabilities_method = function(tree, "capabilities")
        (rep.ok if capabilities_method is not None
         and "probe_capabilities" in calls_named(capabilities_method)
         else rep.fail)("BlueTeamController.capabilities() actually calls probe_capabilities()")

    tree = parsed(agent_registry)
    if tree is None:
        rep.fail("agent/tools/security_tools.py is missing")
    else:
        text = agent_registry.read_text(encoding="utf-8", errors="replace")
        if "from battlefield.soc.tool_catalogue import" not in text:
            rep.fail("agent/tools/security_tools.py does not consume the shared catalogue")
        elif '"iptables -I INPUT -s {ip} -j DROP"' in text:
            rep.fail("agent/tools/security_tools.py restates the block_ip template")
        else:
            rep.ok("the agent registry derives from the catalogue and restates nothing")
        # The parameter itself, not the word "available" in a docstring.
        factory = function(tree, "create_security_tools")
        (rep.ok if factory is not None and "available" in parameter_names(factory) else rep.fail)(
            "create_security_tools() accepts the discovered tool set (`available=`)"
        )

    tree = parsed(server)
    if tree is None:
        rep.fail("battlefield/soc_server.py is missing")
    else:
        (rep.ok if "/capabilities" in route_paths(tree) else rep.fail)(
            "the SOC routes GET /capabilities, the source of T_A"
        )

    # Training builds T_A per row (paper Eq.3). It must not render it from the full
    # catalogue, which is how the Windows-only tool reached the training prompt.
    # The check must not pass on file existence alone -- that passes for an
    # empty file.  The resolver must exist in the module, and the caller must feed
    # its result to `get_tool_descriptions`.
    prompt_rows = root / "training" / "src" / "open_r1" / "utils" / "prompt_rows.py"
    prompt_rows_tree = parsed(prompt_rows)
    if prompt_rows_tree is None:
        rep.fail("training/src/open_r1/utils/prompt_rows.py is missing (or does not parse); "
                 "the training prompt would have no per-row environment to read T_A from")
    elif not defines(prompt_rows_tree, "resolve_row_environment"):
        rep.fail("prompt_rows.py does not define resolve_row_environment(); T_A would have "
                 "no per-row environment source")
    else:
        rep.ok("prompt_rows.py defines resolve_row_environment() (per-row T_A source, Eq.3)")
        rep.ok("training resolves T_A from each dataset row (prompt_rows.py)")
    grpo = root / "training" / "src" / "open_r1" / "grpo.py"
    grpo_tree = parsed(grpo)
    if grpo_tree is not None:
        # AST, not text: `get_tool_descriptions(` inside a comment must not satisfy this,
        # and the call must both pass an argument and come from the row's environment.
        calls = [
            node
            for node in ast.walk(grpo_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get_tool_descriptions"
        ]
        argless = [node.lineno for node in calls if not (node.args or node.keywords)]
        if not calls:
            rep.fail("grpo.py never calls get_tool_descriptions(); the training prompt would "
                     "have no T_A")
        elif argless:
            rep.fail(
                f"grpo.py calls get_tool_descriptions() with no environment argument at "
                f"line(s) {argless}; the training prompt must state the row's tool set "
                f"(paper Eq.3), not the whole catalogue"
            )
        else:
            rep.ok(
                f"grpo.py renders T_A from an environment argument (AST, line(s) "
                f"{[node.lineno for node in calls]})"
            )

    if config.exists():
        try:
            document = json.loads(config.read_text(encoding="utf-8"))
            environment = document.get("environment") or {}
        except (ValueError, AttributeError) as exc:
            rep.fail(f"agent/config.json is not readable JSON: {exc}")
        else:
            if isinstance(environment, dict) and "tools" in environment:
                rep.fail(
                    "agent/config.json declares environment.tools; the available set "
                    "must be probed from the target"
                )
            else:
                rep.ok("agent/config.json keeps no tool list that could contradict the probe")

    # --- 13. "the attack never ran" is classified, not inferred ------------
    rep.section("13. abort_kind: blocked vs broken; 429 is retryable; Eq.20 semantics")
    lab = root / "battlefield" / "attacks" / "sqli_lab.py"
    if not lab.exists():
        rep.warn("battlefield/attacks/sqli_lab.py not present yet")
    else:
        try:
            lab_tree = ast.parse(lab.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            rep.fail(f"sqli_lab.py does not parse: {exc}")
        else:
            if module_binds(lab_tree, "ABORT_KINDS"):
                rep.ok("the producer declares the abort_kind vocabulary")
            else:
                rep.fail(
                    "sqli_lab.py does not declare ABORT_KINDS; the abort classification is "
                    "the only thing that separates 'the defence blocked me' from 'our harness "
                    "broke' (INTERFACES §2.1)"
                )

            # Every fatal abort must name its kind, or it silently degrades to
            # 'unclassified' = unmeasured and a real block loses its credit.
            unclassified_raises: list[str] = []
            for func_name, expected in (
                ("check_health", "target-unreachable"),
                ("calibrate", "oracle-unconfirmed"),
            ):
                fn = None
                for node in ast.walk(lab_tree):
                    if isinstance(node, ast.ClassDef):
                        for item in node.body:
                            if isinstance(item, ast.FunctionDef) and item.name == func_name:
                                fn = item
                if fn is None:
                    rep.fail(f"sqli_lab.py has no {func_name}() to classify")
                    continue
                for sub in ast.walk(fn):
                    if (
                        isinstance(sub, ast.Raise)
                        and isinstance(sub.exc, ast.Call)
                        and getattr(sub.exc.func, "id", None) == "ProbeError"
                    ):
                        kinds = [
                            kw.value.value
                            for kw in sub.exc.keywords
                            if kw.arg == "kind" and isinstance(kw.value, ast.Constant)
                        ]
                        if kinds != [expected]:
                            unclassified_raises.append(f"{func_name}:L{sub.lineno}")
            if unclassified_raises:
                rep.fail(
                    "ProbeError raised without the right kind in "
                    f"{unclassified_raises}; an unclassified abort is treated as unmeasured, "
                    "so a genuine block would earn nothing"
                )
            else:
                rep.ok("every fatal probe abort carries its kind (AST)")

    pev_path = root / "battlefield" / "soc" / "policy_execution_validator.py"
    rtc = root / "battlefield" / "soc" / "red_team_controller.py"
    pipe = root / "battlefield" / "soc" / "execution_pipeline.py"
    for path, names, label in (
        (pev_path, ("ABORT_KINDS", "TARGET_UNREACHABLE"), "the consumer-side vocabulary"),
        (pipe, ("resolve_causation",), "the pre-attack control"),
    ):
        if not path.exists():
            rep.warn(f"{path.name} not present yet")
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            rep.fail(f"{path.name} does not parse: {exc}")
            continue
        missing = [name for name in names if not defines(tree, name)]
        if missing:
            rep.fail(f"{path.name} does not define {missing} ({label})")
        else:
            rep.ok(f"{path.name} defines {', '.join(names)} ({label})")

    if rtc.exists():
        try:
            rtc_tree = ast.parse(rtc.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            rep.fail(f"red_team_controller.py does not parse: {exc}")
        else:
            # Not a text search: `abort_kind` and `TARGET_UNREACHABLE` both appear in the
            # result dict, the log line and the import, so a text match stays green even
            # when the branch that actually consumes the field is disabled.
            guards = []
            for node in ast.walk(rtc_tree):
                if not isinstance(node, ast.If):
                    continue
                tests = node.test.values if isinstance(node.test, ast.BoolOp) else [node.test]
                for test in tests:
                    if (
                        isinstance(test, ast.Compare)
                        and isinstance(test.left, ast.Name)
                        and test.left.id == "abort_kind"
                        and any(
                            isinstance(c, ast.Name) and c.id == "TARGET_UNREACHABLE"
                            for c in test.comparators
                        )
                    ):
                        guards.append(node)
            unmeasured = [
                guard for guard in guards if "_empty_result" in calls_named(guard)
            ]
            if unmeasured:
                rep.ok(
                    "the RTC branches on abort_kind and returns an unmeasured result for "
                    "every kind except target-unreachable (AST)"
                )
            else:
                rep.fail(
                    "red_team_controller.py has no branch that compares abort_kind against "
                    "TARGET_UNREACHABLE and routes the other kinds to _empty_result; an "
                    "all-false stage list must not be accepted as a block without the "
                    "producer saying so (INTERFACES §2.1)"
                )

    # Capacity exhaustion must be retryable and must not be scored as a failure.
    executor_path = root / "agent" / "tools" / "batch_executor.py"
    rewards_path = root / "training" / "src" / "open_r1" / "rewards.py"
    if executor_path.exists():
        try:
            ex_tree = ast.parse(executor_path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            rep.fail(f"batch_executor.py does not parse: {exc}")
        else:
            for name, why in (
                ("parse_retry_after", "the Retry-After header is ignored"),
                ("SOCBusyError", "429 is not distinguished from a bad strategy"),
            ):
                if defines(ex_tree, name):
                    rep.ok(f"batch_executor.py defines {name}")
                else:
                    rep.fail(f"batch_executor.py does not define {name}: {why}")
            if re.search(r"status_code\s*==\s*429", executor_path.read_text(encoding="utf-8")):
                rep.ok("the client handles HTTP 429 explicitly (INTERFACES §3.1)")
            else:
                rep.fail("the client does not test for HTTP 429; capacity exhaustion is retryable")
    if rewards_path.exists():
        text = rewards_path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"RetryableRoundError", text) and re.search(r"EXCLUDED_BATCH_REWARD", text):
            rep.ok("a retryable failure is excluded from the sample, not scored 0")
        else:
            rep.fail(
                "rewards.py does not exclude retryable failures; scoring a busy VM pool 0.0 "
                "teaches the policy that a good strategy failed"
            )

    # The SOC CLI flags must not be accepted and then ignored.
    soc = root / "battlefield" / "soc_server.py"
    if soc.exists():
        try:
            soc_tree = ast.parse(soc.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            rep.fail(f"soc_server.py does not parse: {exc}")
        else:
            config_logging = function(soc_tree, "configure_logging")
            if config_logging is None:
                rep.fail("soc_server.py has no configure_logging()")
            else:
                early_returns = [
                    node
                    for node in config_logging.body
                    if isinstance(node, ast.Return) and node.value is None
                ]
                if early_returns:
                    rep.fail(
                        "configure_logging() can return early, so the later call from main() "
                        "is a no-op and --log-level/--log-file are silently ignored"
                    )
                else:
                    rep.ok("configure_logging() cannot silently no-op (CLI flags take effect)")
                if "getLevelNamesMapping" in calls_named(soc_tree) or "getLevelNamesMapping" in (
                    soc.read_text(encoding="utf-8", errors="replace")
                ):
                    rep.ok("an unknown --log-level is rejected instead of silently accepted")
                else:
                    rep.warn("configure_logging() does not validate the requested level name")

    # --- summary -----------------------------------------------------------
    print("\n" + "=" * 62)
    print(f"PASS {len(rep.passes)}   FAIL {len(rep.failures)}   WARN {len(rep.warnings)}")
    if rep.failures:
        print("\nblocking failures:")
        for f in rep.failures:
            print(f"  - {f}")
        return 1
    print("\nall blocking checks passed" + (" (warnings remain)" if rep.warnings else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
