"""Tests for the alert ingester — severity filtering and the anti-loop guard.

The most important property here is ``_is_own_verdict``: without it the consumer
would re-triage its own high-level re-injected verdicts forever. It is checked
against every marker the injector stamps, plus the negative case (a normal
alert must never be mistaken for a verdict and skipped).
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict, List

from src.ingester import (
    _extract_rule_level,
    _is_own_verdict,
    _matches_required_groups,
    watch_alerts,
)
from src.verdict_contract import VERDICT_LOCATION, VERDICT_RULE_IDS


def test_own_verdict_detected_by_location() -> None:
    assert _is_own_verdict({"location": VERDICT_LOCATION}) is True


def test_own_verdict_detected_by_data_key() -> None:
    assert _is_own_verdict({"data": {VERDICT_LOCATION: {"verdict": "MALICIOUS"}}}) is True


def test_own_verdict_detected_by_rule_id() -> None:
    for rule_id in VERDICT_RULE_IDS:
        assert _is_own_verdict({"rule": {"id": rule_id}}) is True


def test_own_verdict_detected_by_rule_group() -> None:
    assert _is_own_verdict({"rule": {"groups": ["foo", VERDICT_LOCATION]}}) is True


def test_normal_alert_is_not_a_verdict() -> None:
    """A genuine high-level alert must not be misread as our own output."""
    alert = {
        "location": "/var/log/auth.log",
        "rule": {"id": "5712", "level": 10, "groups": ["sshd"]},
        "data": {"srcip": "203.0.113.1"},
    }
    assert _is_own_verdict(alert) is False


def test_extract_rule_level_handles_int_string_and_missing() -> None:
    assert _extract_rule_level({"rule": {"level": 7}}) == 7
    assert _extract_rule_level({"rule": {"level": "9"}}) == 9
    assert _extract_rule_level({"rule": {}}) is None
    assert _extract_rule_level({"rule": {"level": "x"}}) is None
    assert _extract_rule_level({}) is None


def test_required_groups_filter() -> None:
    empty: "frozenset[str]" = frozenset()
    required = frozenset({"anomaly_detector"})
    # An empty requirement matches everything.
    assert _matches_required_groups({"rule": {"groups": ["sshd"]}}, empty) is True
    # A match is found.
    assert _matches_required_groups({"rule": {"groups": ["anomaly_detector"]}}, required) is True
    # No intersection -> filtered out.
    assert _matches_required_groups({"rule": {"groups": ["sshd"]}}, required) is False
    # Missing/!list groups -> filtered out when a requirement is set.
    assert _matches_required_groups({"rule": {}}, required) is False


def _drain_for(generator, expected_count: int, timeout: float = 5.0) -> List[Dict[str, Any]]:
    """Pull up to ``expected_count`` items from a blocking generator in a thread.

    ``watch_alerts`` tails forever, so we collect from a background thread and
    stop once we have what we expect (or the timeout trips), keeping the test
    from hanging if the filtering logic is wrong.
    """
    collected: List[Dict[str, Any]] = []
    done = threading.Event()

    def _run() -> None:
        for item in generator:
            collected.append(item)
            if len(collected) >= expected_count:
                break
        done.set()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    done.wait(timeout)
    return collected


def test_watch_alerts_filters_severity_groups_and_own_verdicts(tmp_path: Path) -> None:
    """End-to-end: only alerts above the threshold and not our own verdicts pass."""
    alerts_file = tmp_path / "alerts.json"
    lines = [
        # Below threshold -> dropped.
        '{"rule":{"level":3,"id":"5715","groups":["sshd"]}}',
        # Our own re-injected verdict -> dropped (anti-loop guard).
        '{"location":"llm_triage","rule":{"level":14,"id":"100110"}}',
        # Malformed JSON -> skipped without crashing.
        "{not json}",
        # Passes: high level, normal alert.
        '{"rule":{"level":10,"id":"5712","groups":["sshd"]},"data":{"srcip":"203.0.113.1"}}',
        # Passes: high level, anomaly group.
        '{"rule":{"level":12,"id":"100100","groups":["anomaly_detector"]}}',
    ]
    alerts_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    generator = watch_alerts(str(alerts_file), min_level=7, from_start=True, poll_interval=0.01)
    passed = _drain_for(generator, expected_count=2)

    assert len(passed) == 2
    assert passed[0]["rule"]["id"] == "5712"
    assert passed[1]["rule"]["id"] == "100100"
