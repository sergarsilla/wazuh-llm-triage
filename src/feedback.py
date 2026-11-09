"""Analyst feedback on triage verdicts.

Lists the verdicts the pipeline re-injected into Wazuh, records whether the
underlying activity was actually benign or malicious, measures how often the
model agreed, and writes every label as a precedent into the local knowledge
base so the RAG step retrieves it for similar alerts.

    python -m src.feedback review [--days 3] [--verdict SUSPICIOUS] [-i]
    python -m src.feedback mark <verdict_id> benign|malicious [--note TEXT]
    python -m src.feedback stats

Re-index after labelling so precedents reach the model:
    docker compose run --rm populate
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, TextIO

from .config import load_config
from .verdict_contract import VERDICT_LOCATION

LABELS = ("benign", "malicious")
VERDICTS = ("FALSE_POSITIVE", "SUSPICIOUS", "MALICIOUS")
DEFAULT_LABELS_PATH = "data_ingest/feedback/labels.jsonl"
DEFAULT_PRECEDENTS_PATH = "data_ingest/knowledge_base/local/analyst_precedents.md"
DEFAULT_CONFIG_PATH = "config/app_config.json"
# How far back `mark` looks for a verdict id it was given.
MARK_LOOKBACK_DAYS = 30
_PREVIEW_CHARS = 160


@dataclass(frozen=True)
class VerdictRecord:
    """One verdict as it was re-injected into Wazuh."""

    verdict_id: str
    timestamp: str
    verdict: str
    risk_level: str
    agent_id: str
    user: str
    command: str
    justification: str
    indicators: str


def _rotated_alert_files(alerts_path: Path, days: int, today: dt.date) -> List[Path]:
    """Return the live alerts file plus Wazuh's rotated daily copies, oldest first."""
    files: List[Path] = []
    for offset in range(days, 0, -1):
        day = today - dt.timedelta(days=offset)
        stem = alerts_path.parent / f"{day:%Y}" / f"{day:%b}" / f"ossec-alerts-{day:%d}.json"
        for candidate in (stem, stem.with_suffix(".json.gz")):
            if candidate.exists():
                files.append(candidate)
                break
    if alerts_path.exists():
        files.append(alerts_path)
    return files


def _open_text(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def parse_verdict(line: str) -> Optional[VerdictRecord]:
    """Return the verdict carried by one alerts.json line, or ``None``."""
    if VERDICT_LOCATION not in line:
        return None
    try:
        alert = json.loads(line)
    except ValueError:
        return None
    payload = (alert.get("data") or {}).get(VERDICT_LOCATION)
    if not isinstance(payload, dict) or payload.get("verdict") not in VERDICTS:
        return None
    return VerdictRecord(
        verdict_id=str(alert.get("id", "")),
        timestamp=str(alert.get("timestamp", "")),
        verdict=str(payload.get("verdict", "")),
        risk_level=str(payload.get("risk_level", "")),
        agent_id=str(payload.get("agent_id", "")),
        user=str(payload.get("user", "")),
        command=str(payload.get("command", "")),
        justification=str(payload.get("justification", "")),
        indicators=str(payload.get("indicators", "")),
    )


def read_verdicts(
    alerts_path: Path, days: int, today: Optional[dt.date] = None
) -> Iterator[VerdictRecord]:
    """Yield every verdict from the last ``days`` rotated files and the live file."""
    for path in _rotated_alert_files(alerts_path, days, today or dt.date.today()):
        with _open_text(path) as handle:
            for line in handle:
                record = parse_verdict(line)
                if record is not None:
                    yield record


def load_labels(labels_path: Path) -> Dict[str, dict]:
    """Return the latest label per verdict id; a later line overrides an earlier one."""
    labels: Dict[str, dict] = {}
    if not labels_path.exists():
        return labels
    with open(labels_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("label") in LABELS and entry.get("verdict_id"):
                labels[str(entry["verdict_id"])] = entry
    return labels


def append_label(labels_path: Path, record: VerdictRecord, label: str, note: str) -> dict:
    """Persist one label next to the verdict it judges."""
    if label not in LABELS:
        raise ValueError(f"label must be one of {LABELS}, got {label!r}")
    entry = {
        **asdict(record),
        "label": label,
        "note": note,
        "labelled_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    with open(labels_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def summarise(labels: Iterable[dict]) -> Dict[str, Counter]:
    """Count labels per verdict class: ``{verdict: Counter({label: n})}``."""
    table: Dict[str, Counter] = {verdict: Counter() for verdict in VERDICTS}
    for entry in labels:
        table.setdefault(entry["verdict"], Counter())[entry["label"]] += 1
    return table


def render_precedents(labels: Iterable[dict]) -> str:
    """Render labels as knowledge-base paragraphs, one per distinct command."""
    latest: Dict[str, dict] = {}
    for entry in sorted(labels, key=lambda item: item.get("labelled_at", "")):
        if entry.get("command"):
            latest[entry["command"]] = entry
    paragraphs = ["# Analyst-reviewed precedents"]
    for entry in latest.values():
        text = (
            f"Analyst precedent: user {entry['user'] or 'unknown'} on agent "
            f"{entry['agent_id']} ran `{entry['command']}`. The triage verdict was "
            f"{entry['verdict']}; the analyst labelled the activity "
            f"{entry['label'].upper()}."
        )
        if entry.get("note"):
            text += f" Analyst note: {entry['note']}"
        paragraphs.append(text)
    return "\n\n".join(paragraphs) + "\n"


def write_precedents(precedents_path: Path, labels: Iterable[dict]) -> None:
    precedents_path.parent.mkdir(parents=True, exist_ok=True)
    precedents_path.write_text(render_precedents(labels), encoding="utf-8")


def _format_row(record: VerdictRecord, label: Optional[str]) -> str:
    mark = f"[{label}]" if label else "[ ]"
    command = record.command.replace("\n", " ")[:_PREVIEW_CHARS]
    flags = f" {{{record.indicators}}}" if record.indicators else ""
    return (
        f"{mark:<12}{record.verdict_id}  {record.timestamp[:16]}  "
        f"{record.verdict:<14} agent={record.agent_id}{flags}\n             {command}"
    )


def _ask_label() -> Optional[str]:
    while True:
        answer = input("  [b]enign / [m]alicious / [s]kip / [q]uit > ").strip().lower()
        if answer in ("b", "m"):
            return "benign" if answer == "b" else "malicious"
        if answer == "s":
            return ""
        if answer == "q":
            return None


def cmd_review(args: argparse.Namespace, alerts_path: Path, labels_path: Path, precedents_path: Path) -> int:
    labels = load_labels(labels_path)
    records = [
        record for record in read_verdicts(alerts_path, args.days)
        if args.verdict in ("all", record.verdict)
        and not (args.interactive and record.verdict_id in labels)
    ]
    for record in records:
        current = labels.get(record.verdict_id, {}).get("label")
        print(_format_row(record, current))
        if not args.interactive:
            continue
        print(f"             why: {record.justification[:_PREVIEW_CHARS]}")
        label = _ask_label()
        if label is None:
            break
        if label:
            note = input("  note (optional) > ").strip()
            labels[record.verdict_id] = append_label(labels_path, record, label, note)
    if args.interactive:
        write_precedents(precedents_path, labels.values())
    print(f"\n{len(records)} verdict(s) shown.")
    return 0


def cmd_mark(args: argparse.Namespace, alerts_path: Path, labels_path: Path, precedents_path: Path) -> int:
    record = next(
        (r for r in read_verdicts(alerts_path, MARK_LOOKBACK_DAYS) if r.verdict_id == args.verdict_id),
        None,
    )
    if record is None:
        print(f"No verdict {args.verdict_id} in the last {MARK_LOOKBACK_DAYS} days.", file=sys.stderr)
        return 1
    labels = load_labels(labels_path)
    labels[record.verdict_id] = append_label(labels_path, record, args.label, args.note)
    write_precedents(precedents_path, labels.values())
    print(_format_row(record, args.label))
    return 0


def cmd_stats(_args: argparse.Namespace, _alerts: Path, labels_path: Path, _precedents: Path) -> int:
    labels = list(load_labels(labels_path).values())
    if not labels:
        print("No labels yet. Run `review -i` to start.")
        return 0
    table = summarise(labels)
    print(f"{'verdict':<16}{'benign':>8}{'malicious':>11}")
    for verdict, counts in table.items():
        print(f"{verdict:<16}{counts['benign']:>8}{counts['malicious']:>11}")
    missed = table["FALSE_POSITIVE"]["malicious"]
    false_alarms = table["MALICIOUS"]["benign"]
    decided = sum(table[v][label] for v in ("FALSE_POSITIVE", "MALICIOUS") for label in LABELS)
    agreed = table["FALSE_POSITIVE"]["benign"] + table["MALICIOUS"]["malicious"]
    print(f"\nlabelled: {len(labels)}  missed threats: {missed}  false alarms: {false_alarms}")
    if decided:
        print(f"agreement on decided verdicts: {agreed}/{decided} ({agreed / decided:.0%})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m src.feedback", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="list recent verdicts, optionally labelling them")
    review.add_argument("--days", type=int, default=1, help="rotated days to include besides today")
    review.add_argument("--verdict", choices=("all",) + VERDICTS, default="all")
    review.add_argument("-i", "--interactive", action="store_true", help="label unlabelled verdicts one by one")
    review.set_defaults(handler=cmd_review)

    mark = sub.add_parser("mark", help="label one verdict by its id")
    mark.add_argument("verdict_id")
    mark.add_argument("label", choices=LABELS)
    mark.add_argument("--note", default="")
    mark.set_defaults(handler=cmd_mark)

    stats = sub.add_parser("stats", help="agreement between verdicts and labels")
    stats.set_defaults(handler=cmd_stats)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(os.environ.get("CONFIG_PATH", DEFAULT_CONFIG_PATH))
    alerts_path = Path(config["wazuh_alerts_path"])
    labels_path = Path(os.environ.get("FEEDBACK_LABELS_PATH", DEFAULT_LABELS_PATH))
    precedents_path = Path(os.environ.get("FEEDBACK_PRECEDENTS_PATH", DEFAULT_PRECEDENTS_PATH))
    return int(args.handler(args, alerts_path, labels_path, precedents_path))


if __name__ == "__main__":
    sys.exit(main())
