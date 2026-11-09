"""Tests for the analyst feedback CLI."""

from __future__ import annotations

import datetime as dt
import gzip
import json
from pathlib import Path

import pytest

from src.feedback import (
    append_label,
    load_labels,
    main,
    parse_verdict,
    read_verdicts,
    render_precedents,
    summarise,
)

TODAY = dt.date(2026, 11, 9)


def _verdict_line(verdict_id: str, verdict: str, command: str) -> str:
    return json.dumps({
        "id": verdict_id,
        "timestamp": "2026-11-09T09:40:13.000+0000",
        "location": "llm_triage",
        "data": {"llm_triage": {
            "verdict": verdict, "risk_level": "LOW", "agent_id": "023",
            "user": "admin", "command": command, "justification": "routine",
            "indicators": "persistence_config",
        }},
    })


def _anomaly_line() -> str:
    return json.dumps({"id": "1.1", "location": "anomaly_detector", "data": {}})


@pytest.fixture()
def alerts_dir(tmp_path: Path) -> Path:
    live = tmp_path / "alerts.json"
    live.write_text(_anomaly_line() + "\n" + _verdict_line("2.2", "FALSE_POSITIVE", "crontab -e") + "\n")
    rotated = tmp_path / "2026" / "Nov" / "ossec-alerts-08.json.gz"
    rotated.parent.mkdir(parents=True)
    with gzip.open(rotated, "wt") as handle:
        handle.write(_verdict_line("1.9", "SUSPICIOUS", "docker ps") + "\n")
    return tmp_path


def test_parse_verdict_ignores_non_verdict_alerts() -> None:
    assert parse_verdict(_anomaly_line()) is None
    assert parse_verdict("not json llm_triage") is None


def test_read_verdicts_includes_rotated_days_oldest_first(alerts_dir: Path) -> None:
    ids = [r.verdict_id for r in read_verdicts(alerts_dir / "alerts.json", days=1, today=TODAY)]

    assert ids == ["1.9", "2.2"]


def test_read_verdicts_without_history_reads_only_the_live_file(alerts_dir: Path) -> None:
    ids = [r.verdict_id for r in read_verdicts(alerts_dir / "alerts.json", days=0, today=TODAY)]

    assert ids == ["2.2"]


def test_a_later_label_overrides_an_earlier_one(tmp_path: Path) -> None:
    record = parse_verdict(_verdict_line("2.2", "FALSE_POSITIVE", "crontab -e"))
    labels_path = tmp_path / "labels.jsonl"

    append_label(labels_path, record, "benign", "")
    append_label(labels_path, record, "malicious", "was not me")

    labels = load_labels(labels_path)
    assert labels["2.2"]["label"] == "malicious"
    assert labels["2.2"]["note"] == "was not me"


def test_append_label_rejects_unknown_labels(tmp_path: Path) -> None:
    record = parse_verdict(_verdict_line("2.2", "FALSE_POSITIVE", "crontab -e"))

    with pytest.raises(ValueError):
        append_label(tmp_path / "labels.jsonl", record, "maybe", "")


def test_summarise_counts_missed_threats_per_verdict() -> None:
    labels = [
        {"verdict": "FALSE_POSITIVE", "label": "benign"},
        {"verdict": "FALSE_POSITIVE", "label": "malicious"},
        {"verdict": "MALICIOUS", "label": "benign"},
    ]

    table = summarise(labels)

    assert table["FALSE_POSITIVE"]["malicious"] == 1
    assert table["MALICIOUS"]["benign"] == 1


def test_precedents_keep_one_paragraph_per_command_latest_wins() -> None:
    base = {"user": "admin", "agent_id": "023", "verdict": "FALSE_POSITIVE", "command": "crontab -e"}
    labels = [
        {**base, "label": "benign", "note": "", "labelled_at": "2026-11-09T10:00:00"},
        {**base, "label": "malicious", "note": "unknown cron", "labelled_at": "2026-11-09T11:00:00"},
    ]

    text = render_precedents(labels)

    assert text.count("Analyst precedent") == 1
    assert "MALICIOUS" in text and "unknown cron" in text
    paragraphs = [p for p in text.split("\n\n") if p.startswith("Analyst precedent")]
    assert all(len(p) >= 40 for p in paragraphs)


def test_mark_writes_label_and_precedents(alerts_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    labels_path = tmp_path / "out" / "labels.jsonl"
    precedents_path = tmp_path / "out" / "precedents.md"
    monkeypatch.setenv("WAZUH_ALERTS_PATH", str(alerts_dir / "alerts.json"))
    monkeypatch.setenv("FEEDBACK_LABELS_PATH", str(labels_path))
    monkeypatch.setenv("FEEDBACK_PRECEDENTS_PATH", str(precedents_path))

    assert main(["mark", "2.2", "benign", "--note", "my own cron edit"]) == 0

    assert load_labels(labels_path)["2.2"]["label"] == "benign"
    assert "my own cron edit" in precedents_path.read_text()


def test_mark_fails_for_an_unknown_verdict(alerts_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_ALERTS_PATH", str(alerts_dir / "alerts.json"))
    monkeypatch.setenv("FEEDBACK_LABELS_PATH", str(tmp_path / "labels.jsonl"))
    monkeypatch.setenv("FEEDBACK_PRECEDENTS_PATH", str(tmp_path / "precedents.md"))

    assert main(["mark", "9.9", "benign"]) == 1
