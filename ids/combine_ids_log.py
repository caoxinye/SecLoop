# SPDX-License-Identifier: Apache-2.0
"""Suricata ``fast.log`` alert summarizer -- the SecLoop prompt section ``C``.

This module implements the alert summarizer ``S_r`` of Eq. 2 in the SecLoop
paper: raw IDS alerts are grouped by ``(attack_type, source_ip)`` inside a
sliding time window of ``window_s`` seconds and compressed into a short,
structured natural-language report.  That report is the ``C`` half of the
policy-generation prompt ``P = [C, T_A, E]`` (``docs/INTERFACES.md`` sections
8 and 9).

Design notes
------------
* The input is the **real** ``fast.log`` written by Suricata.  This module
  never invents, rewrites or persists alert records -- "synthesised alert
  logs" are explicitly out of scope for this project.
* ``attack_type`` is the rule message with a trailing
  ``"<family> - <variant>"`` discriminator collapsed, so that a scanner
  firing hundreds of near-identical signatures
  (``SQL Injection Attempt - '`` vs ``SQL Injection Attempt - (`` ...) becomes
  one readable episode instead of hundreds of lines.  The distinct variants
  are still reported inside the episode.
* Alerts are sorted by timestamp before aggregation, so the output is
  deterministic regardless of the order lines arrive in.
* Empty input (or input without a single parsable alert) yields ``""``
  exactly, as required by the frozen contract.

Public API
----------
``summarize_fastlog(path, window_s=300) -> str``
``summarize_lines(lines, window_s=300) -> str``
``parse_fastlog_line(line) -> Alert | None``

Command line
------------
``python ids/combine_ids_log.py --fastlog /var/log/suricata/fast.log``
(omit ``--fastlog`` or pass ``-`` to read from stdin).
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Sequence

LOGGER = logging.getLogger("secloop.ids.summarizer")

__all__ = [
    "Alert",
    "parse_fastlog_line",
    "summarize_fastlog",
    "summarize_lines",
]

#: Default sliding-window width, in seconds (INTERFACES.md section 9).
DEFAULT_WINDOW_S = 300

#: Upper bound on rendered episodes, so ``C`` stays prompt-sized no matter how
#: long the log is.  Anything above this is reported as a suppressed count.
DEFAULT_MAX_EPISODES = 50

#: How many distinct signatures / endpoints are quoted per episode.
DEFAULT_MAX_EXAMPLES = 3
_MAX_TARGETS = 2
_MAX_SIDS = 5

# Suricata fast.log line, e.g.
#   03/26/2025-22:03:25.977231  [**] [1:100033:1] SQL Injection Attempt - ' [**]
#   [Classification: Web Application Attack] [Priority: 1] {TCP}
#   192.168.75.129:54228 -> 192.168.75.142:80
_FASTLOG_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"\s+\[\*\*\]\s+\[\d+:(?P<sid>\d+):\d+\]\s+"
    r"(?P<msg>.*?)\s+"
    r"\[\*\*\]\s+\[Classification:\s*(?P<classification>.*?)\]\s+"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<protocol>[A-Za-z0-9]+)\}\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<src_port>\d+)\s*->\s*"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<dst_port>\d+)"
)

#: ``<family> - <variant>`` discriminator used by the signature sets that ship
#: with this repository (and by the standard ET/OWASP SQLi rule sets).
_VARIANT_SPLIT_RE = re.compile(r"^(?P<family>.+?)\s+-\s+(?P<variant>.+)$")


@dataclass(slots=True)
class Alert:
    """One parsed Suricata ``fast.log`` alert."""

    timestamp: datetime
    sid: int
    msg: str
    attack_type: str
    classification: str
    priority: int
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

    @property
    def target(self) -> str:
        """``<dst_ip>:<dst_port>`` -- the endpoint the signature fired on."""
        return f"{self.dst_ip}:{self.dst_port}"


@dataclass(slots=True)
class _Episode:
    """A burst of alerts of one ``(attack_type, source_ip)`` pair."""

    attack_type: str
    src_ip: str
    start: datetime
    end: datetime
    count: int = 1
    priority: int = 9
    classifications: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    variants: set[str] = field(default_factory=set)
    sids: set[int] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    targets: Counter = field(default_factory=Counter)


def _signature_family(msg: str) -> str:
    """Collapse ``"<family> - <variant>"`` into ``"<family>"``.

    Signatures that carry no discriminator are returned unchanged.  This keeps
    the grouping key small enough for a prompt while losing no information
    that the episode does not re-report as a variant.
    """
    text = " ".join(msg.split())
    match = _VARIANT_SPLIT_RE.match(text)
    if match:
        return match.group("family").strip()
    return text


def _parse_timestamp(raw: str) -> datetime | None:
    """Parse the ``MM/DD/YYYY-HH:MM:SS[.ffffff]`` fast.log timestamp."""
    for fmt in ("%m/%d/%Y-%H:%M:%S.%f", "%m/%d/%Y-%H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def parse_fastlog_line(line: str) -> Alert | None:
    """Parse one Suricata ``fast.log`` line.

    Returns ``None`` for blank lines, banners and anything else that is not a
    classic ``fast.log`` alert record.  No line is ever "repaired" or
    fabricated: unparsable input is simply reported (and counted) upstream.
    """
    text = line.strip()
    if not text:
        return None
    match = _FASTLOG_RE.match(text)
    if match is None:
        return None
    timestamp = _parse_timestamp(match.group("ts"))
    if timestamp is None:
        return None
    msg = " ".join(match.group("msg").split())
    return Alert(
        timestamp=timestamp,
        sid=int(match.group("sid")),
        msg=msg,
        attack_type=_signature_family(msg),
        classification=" ".join(match.group("classification").split()),
        priority=int(match.group("priority")),
        protocol=match.group("protocol").upper(),
        src_ip=match.group("src_ip"),
        src_port=int(match.group("src_port")),
        dst_ip=match.group("dst_ip"),
        dst_port=int(match.group("dst_port")),
    )


def _aggregate(alerts: Sequence[Alert], window_s: int) -> list[_Episode]:
    """Fold chronologically sorted alerts into sliding-window episodes.

    ``alerts`` must already be sorted by timestamp.  For every
    ``(attack_type, source_ip)`` group the newest open episode absorbs the
    incoming alert while ``alert.ts - episode.end <= window_s``; otherwise a
    fresh episode is opened.
    """
    window = timedelta(seconds=window_s)
    open_episodes: dict[tuple[str, str], list[_Episode]] = defaultdict(list)
    for alert in alerts:
        key = (alert.attack_type, alert.src_ip)
        bucket = open_episodes[key]
        if bucket and alert.timestamp - bucket[-1].end <= window:
            episode = bucket[-1]
            episode.count += 1
            if alert.timestamp > episode.end:
                episode.end = alert.timestamp
        else:
            episode = _Episode(
                attack_type=alert.attack_type,
                src_ip=alert.src_ip,
                start=alert.timestamp,
                end=alert.timestamp,
            )
            bucket.append(episode)
        episode.priority = min(episode.priority, alert.priority)
        episode.classifications.add(alert.classification)
        episode.protocols.add(alert.protocol)
        episode.variants.add(alert.msg)
        episode.sids.add(alert.sid)
        episode.dst_ips.add(alert.dst_ip)
        episode.targets[alert.target] += 1

    episodes = [episode for bucket in open_episodes.values() for episode in bucket]
    episodes.sort(key=lambda e: (e.start, e.attack_type, e.src_ip))
    return episodes


def _render_episode(index: int, episode: _Episode, max_examples: int) -> str:
    """Render one episode as a single structured natural-language line."""
    duration_s = int((episode.end - episode.start).total_seconds())
    targets = [f"{target} ({count} alert(s))" for target, count in episode.targets.most_common(_MAX_TARGETS)]
    hidden_targets = len(episode.targets) - len(targets)
    if hidden_targets > 0:
        targets.append(f"+{hidden_targets} more")

    variants = sorted(episode.variants)[:max_examples]
    variant_text = ", ".join(json.dumps(variant, ensure_ascii=False) for variant in variants)
    hidden_variants = len(episode.variants) - len(variants)
    if hidden_variants > 0:
        variant_text += f", +{hidden_variants} more"

    sids = ",".join(str(sid) for sid in sorted(episode.sids)[:_MAX_SIDS])
    hidden_sids = len(episode.sids) - _MAX_SIDS
    if hidden_sids > 0:
        sids += f",+{hidden_sids}"
    classifications = "/".join(sorted(episode.classifications)) or "unknown"
    protocols = "/".join(sorted(episode.protocols)) or "unknown"

    return (
        f"{index}. '{episode.attack_type}' | source {episode.src_ip} over {protocols} | "
        f"{episode.start.isoformat(sep=' ', timespec='seconds')} -> "
        f"{episode.end.isoformat(sep=' ', timespec='seconds')} "
        f"({duration_s}s, {episode.count} alert(s)) | "
        f"targets {', '.join(targets) or 'unknown'} | "
        f"classification {classifications} | max priority {episode.priority} | "
        f"{len(episode.variants)} signature variant(s): {variant_text or 'n/a'} | "
        f"rule sid {sids or 'n/a'}"
    )


def _render(
    episodes: Sequence[_Episode],
    window_s: int,
    max_episodes: int,
    max_examples: int,
) -> str:
    """Render the whole summary; returns ``""`` when there is nothing to say."""
    if not episodes:
        return ""

    total_alerts = sum(episode.count for episode in episodes)
    source_ips = {episode.src_ip for episode in episodes}
    target_ips = {ip for episode in episodes for ip in episode.dst_ips}
    shown = list(episodes[:max_episodes])

    lines = [
        f"Suricata alert summary (sliding window {window_s}s): "
        f"{len(episodes)} attack episode(s), {total_alerts} alert(s), "
        f"{len(source_ips)} source IP(s), {len(target_ips)} target IP(s)."
    ]
    lines.extend(
        _render_episode(index, episode, max_examples) for index, episode in enumerate(shown, start=1)
    )
    if len(episodes) > len(shown):
        lines.append(
            f"... {len(episodes) - len(shown)} further episode(s) suppressed "
            f"(raise max_episodes to include them)."
        )
    return "\n".join(lines)


def summarize_lines(
    lines: Iterable[str],
    window_s: int = DEFAULT_WINDOW_S,
    *,
    max_episodes: int = DEFAULT_MAX_EPISODES,
    max_examples: int = DEFAULT_MAX_EXAMPLES,
) -> str:
    """Compress an iterable of **real** Suricata ``fast.log`` lines into ``C``.

    Args:
        lines: Raw ``fast.log`` lines (typically from ``open(path)``).
        window_s: Sliding-window width in seconds.  Alerts of the same
            ``(attack_type, source_ip)`` pair no further apart than this are
            folded into one episode.
        max_episodes: Hard cap on rendered episodes (prompt-size guard).
        max_examples: Distinct signature variants quoted per episode.

    Returns:
        A structured natural-language summary, or ``""`` when the input holds
        no parsable alert.
    """
    if window_s <= 0:
        raise ValueError("window_s must be a positive number of seconds")
    if max_episodes <= 0:
        raise ValueError("max_episodes must be positive")

    alerts: list[Alert] = []
    skipped = 0
    for raw in lines:
        alert = parse_fastlog_line(raw)
        if alert is None:
            if raw and raw.strip():
                skipped += 1
            continue
        alerts.append(alert)

    if skipped:
        LOGGER.warning("ignored %d non-alert line(s) in fast.log input", skipped)
    if not alerts:
        LOGGER.info("no parsable alert in input; returning an empty summary")
        return ""

    alerts.sort(key=lambda alert: (alert.timestamp, alert.src_ip, alert.attack_type))
    episodes = _aggregate(alerts, window_s)
    return _render(episodes, window_s, max_episodes, max_examples)


def _stdin_text_stream() -> Iterable[str]:
    """Read stdin as UTF-8 regardless of the host locale.

    Iterating ``sys.stdin`` directly inherits the console encoding (cp1252,
    cp936, ...), which would both corrupt alert text and be able to raise
    ``UnicodeDecodeError`` on a partly binary fast.log.  Suricata always writes
    UTF-8, so decode it as such and replace undecodable bytes instead.
    """
    raw = getattr(sys.stdin, "buffer", None)
    if raw is None:  # pragma: no cover - stdin already a text stream (tests)
        return sys.stdin
    return io.TextIOWrapper(raw, encoding="utf-8", errors="replace")


def summarize_fastlog(
    path: str | Path,
    window_s: int = DEFAULT_WINDOW_S,
    *,
    max_episodes: int = DEFAULT_MAX_EPISODES,
    max_examples: int = DEFAULT_MAX_EXAMPLES,
) -> str:
    """Summarize a **real** Suricata ``fast.log`` file (see :func:`summarize_lines`).

    Args:
        path: Path to the ``fast.log`` file, or ``"-"`` to read stdin.
        window_s: Sliding-window width in seconds.
        max_episodes: Hard cap on rendered episodes (prompt-size guard).
        max_examples: Distinct signature variants quoted per episode.

    Raises:
        FileNotFoundError: If ``path`` does not exist.  Failing loudly is
            deliberate -- silently returning ``""`` for a missing log would
            hide a broken IDS pipeline.
    """
    if str(path) == "-":
        LOGGER.info("summarizing fast.log alerts from stdin")
        return summarize_lines(
            _stdin_text_stream(), window_s, max_episodes=max_episodes, max_examples=max_examples
        )

    log_path = Path(path)
    if not log_path.is_file():
        raise FileNotFoundError(f"fast.log not found: {log_path}")

    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        summary = summarize_lines(
            handle, window_s, max_episodes=max_episodes, max_examples=max_examples
        )
    LOGGER.info(
        "summarized %s (window_s=%s): %s line(s) of summary",
        log_path,
        window_s,
        len(summary.splitlines()),
    )
    return summary


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compress real Suricata fast.log alerts into the SecLoop prompt "
            "section C (paper Eq.2). Reads stdin when --fastlog is omitted."
        )
    )
    parser.add_argument(
        "--fastlog",
        "-f",
        default="-",
        help="path to the Suricata fast.log file, or '-' for stdin (default: stdin)",
    )
    parser.add_argument(
        "--window-s",
        type=int,
        default=DEFAULT_WINDOW_S,
        help=f"sliding-window width in seconds (default: {DEFAULT_WINDOW_S})",
    )
    parser.add_argument(
        "--max-episodes",
        type=int,
        default=DEFAULT_MAX_EPISODES,
        help=f"maximum number of episodes to render (default: {DEFAULT_MAX_EPISODES})",
    )
    parser.add_argument(
        "--max-examples",
        type=int,
        default=DEFAULT_MAX_EXAMPLES,
        help=f"signature variants quoted per episode (default: {DEFAULT_MAX_EXAMPLES})",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="diagnostic verbosity on stderr (default: WARNING)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point: write the summary (``C``) to stdout."""
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        summary = summarize_fastlog(
            args.fastlog,
            window_s=args.window_s,
            max_episodes=args.max_episodes,
            max_examples=args.max_examples,
        )
    except FileNotFoundError as exc:
        LOGGER.error("%s", exc)
        return 2
    except (OSError, ValueError) as exc:
        LOGGER.error("failed to summarize %s: %s", args.fastlog, exc)
        return 1
    # An empty summary is a valid answer; print nothing at all so that the
    # caller's "empty input -> empty string" assertion holds byte for byte.
    if summary:
        sys.stdout.write(summary + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI wiring
    raise SystemExit(main())
