# SPDX-License-Identifier: Apache-2.0
"""Training-side view of the alert summarizer ``S_r`` (paper Eq. 2; ``INTERFACES.md`` §8/§9).

``C = S_r(L)`` compresses a stream of raw IDS alerts into the standardized attack
summaries that form the ``C`` section of the prompt ``P = [C, T_A, E]``.

Authority
---------
``INTERFACES.md`` §9 makes ``ids/combine_ids_log.py`` the owner of ``S_r``.  This
module therefore contains **no canonical summarizer** - it re-exports
:func:`ids.combine_ids_log.summarize_lines` /
:func:`ids.combine_ids_log.summarize_fastlog` and adapts them to the training
prompt, exactly like ``utils/security_tools.py`` re-exports the tool registry
(§6).  One authority, one content grammar: the ``C`` the model sees during
training is produced by the same code that produces it on the evaluation path, so
the two prompts cannot drift apart.

Canonical input
---------------
The dataset's ``alerts`` column holds **raw Suricata ``fast.log`` text** (one alert
line per line).  That keeps the corpus faithful to the rule that alerts must come from
a real IDS rather than from a stored, pre-digested summary.

Legacy digest grammar
---------------------
A *pre-aggregated digest*
(``Time range: ... detected N times '<signature>' attack, source IP: ..., target:
..., risk level: N``) is **not** the dataset contract and **not** the default path; it
is readable only through :func:`parse_legacy_digest`, so a file written in that
grammar can still be inspected explicitly.  Feeding digest text to the canonical path
is correct behaviour, not a failure: ``ids.summarize_lines`` finds no parsable
``fast.log`` line, returns ``""``, and ``grpo.py`` drops that row with a logged error
instead of silently summarising it with a different grammar.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from open_r1._syspath import ensure_repo_root_on_path

ensure_repo_root_on_path()

from ids.combine_ids_log import (  # noqa: E402  (import after sys.path shim)
    DEFAULT_MAX_EPISODES,
    DEFAULT_MAX_EXAMPLES,
    DEFAULT_WINDOW_S,
    summarize_fastlog,
    summarize_lines,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_MAX_EPISODES",
    "DEFAULT_MAX_EXAMPLES",
    "DEFAULT_WINDOW_S",
    "AlertRecord",
    "AttackSummary",
    "Summarizer",
    "parse_legacy_digest",
    "split_fastlog_lines",
    "summarize_fastlog",
    "summarize_lines",
]


def split_fastlog_lines(raw_alerts: str) -> List[str]:
    """Split a dataset ``alerts`` cell into individual ``fast.log`` lines."""
    if not raw_alerts:
        return []
    return [line for line in str(raw_alerts).splitlines() if line.strip()]


class Summarizer:
    """``S_r`` adapter for the training prompt; delegates to ``ids.summarize_lines``.

    Args:
        window_s: sliding-window width in seconds, forwarded to the authority.
    """

    def __init__(self, window_s: int = DEFAULT_WINDOW_S) -> None:
        self.window_s = int(window_s)

    def summarize_to_str(self, raw_alerts: str) -> str:
        """Return the ``C`` section for the prompt, or ``""`` when there is none.

        An empty input yields an empty string (``INTERFACES.md`` §9).  When the text
        holds no parsable ``fast.log`` line the authority returns ``""`` as well and a
        warning is logged here, because the caller will drop the row.
        """
        lines = split_fastlog_lines(raw_alerts)
        if not lines:
            return ""

        summary = summarize_lines(lines, window_s=self.window_s)
        if not summary:
            logger.warning(
                "ids.summarize_lines parsed no fast.log line out of %d line(s); the canonical path "
                "will not fall back to a different grammar (INTERFACES.md §9)",
                len(lines),
            )
        return summary


# --------------------------------------------------------------------------------------
# Legacy pre-aggregated digest grammar: inspection only, never the default path.
# --------------------------------------------------------------------------------------
_LEGACY_ALERT_RE = re.compile(
    r"Time range:\s*(?P<time_start>\S+\s+\S+)\s+to\s+(?P<time_end>\S+\s+\S+)\s*,"
    r"\s*detected\s+(?P<count>\d+)\s+times?\s+'(?P<attack_type>[^']+)'"
    r"\s*(?:attack)?\s*,"
    r"\s*source IP:\s*(?P<source_ip>\S+)\s*,"
    r"\s*target:\s*(?P<target>\S+)\s*,"
    r"\s*risk level:\s*(?P<risk_level>\d+)",
    re.IGNORECASE,
)


@dataclass
class AlertRecord:
    """Parsed representation of one legacy digest line (not a Suricata alert)."""

    time_start: str
    time_end: str
    detection_count: int
    attack_type: str
    source_ip: str
    target: str
    risk_level: int


@dataclass
class AttackSummary:
    """Legacy ``(attack_type, source_ip)`` group rendered by :meth:`format`."""

    attack_type: str
    source_ip: str
    total_detections: int
    alert_count: int
    time_start: str
    time_end: str
    targets: List[str]
    max_risk_level: int

    def format(self) -> str:
        """Render the legacy ``C_i`` line (digest style)."""
        targets_str = ", ".join(sorted(set(self.targets)))
        return (
            f"[{self.attack_type}] source={self.source_ip} "
            f"detections={self.total_detections} "
            f"span={self.time_start}..{self.time_end} "
            f"targets={targets_str} "
            f"risk={self.max_risk_level}"
        )


def _parse_legacy_line(line: str) -> Optional[AlertRecord]:
    match = _LEGACY_ALERT_RE.search(line)
    if not match:
        return None
    try:
        return AlertRecord(
            time_start=match.group("time_start"),
            time_end=match.group("time_end"),
            detection_count=int(match.group("count")),
            attack_type=match.group("attack_type").strip(),
            source_ip=match.group("source_ip"),
            target=match.group("target"),
            risk_level=int(match.group("risk_level")),
        )
    except (ValueError, IndexError):
        return None


def parse_legacy_digest(raw_alerts: str) -> str:
    """Render the legacy pre-aggregated digest. **Not** the dataset contract.

    Kept only so a corpus written in that grammar can be inspected explicitly;
    the canonical ``C`` path is :meth:`Summarizer.summarize_to_str` ->
    ``ids.summarize_lines`` (``INTERFACES.md`` §9).  Returns ``""`` for empty input
    and forwards unparsable text unchanged so nothing is silently discarded.
    """
    records: List[AlertRecord] = []
    for line in (raw_alerts or "").splitlines():
        line = line.strip()
        if not line:
            continue
        record = _parse_legacy_line(line)
        if record is not None:
            records.append(record)

    if not records:
        return raw_alerts if raw_alerts and raw_alerts.strip() else ""

    groups: Dict[str, List[AlertRecord]] = {}
    for record in records:
        groups.setdefault(f"{record.attack_type}|||{record.source_ip}", []).append(record)

    summaries: List[AttackSummary] = []
    for group in groups.values():
        summaries.append(
            AttackSummary(
                attack_type=group[0].attack_type,
                source_ip=group[0].source_ip,
                total_detections=sum(record.detection_count for record in group),
                alert_count=len(group),
                time_start=min(record.time_start for record in group),
                time_end=max(record.time_end for record in group),
                targets=[record.target for record in group],
                max_risk_level=max(record.risk_level for record in group),
            )
        )
    summaries.sort(key=lambda summary: (summary.max_risk_level, summary.total_detections), reverse=True)
    return "\n".join(summary.format() for summary in summaries)
