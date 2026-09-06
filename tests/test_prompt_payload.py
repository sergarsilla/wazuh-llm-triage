"""Tests for what the alert block of the prompt actually carries."""

from __future__ import annotations

import json

from src.llm_client import OllamaSOCClient, _without_redundant_full_log

ANOMALY_DATA = {
    "anomaly_detector": {
        "agent_id": "023",
        "agent_name": "my-server-3",
        "rule_id": "100100",
        "anomaly_score": "0.076956",
        "severity": "1.210000",
        "process_name": "journalctl",
    }
}

# Wazuh re-serialises the injected payload into full_log, coercing the decoded
# fields to strings on the way, so the two copies differ in type but not value.
REDUNDANT_FULL_LOG = json.dumps(
    {
        "anomaly_detector": {
            "agent_id": "023",
            "agent_name": "my-server-3",
            "rule_id": 100100,
            "anomaly_score": 0.076956,
            "severity": 1.21,
            "process_name": "journalctl",
        }
    }
)


def test_redundant_full_log_is_dropped() -> None:
    alert = {"rule": {"id": "100100"}, "data": ANOMALY_DATA, "full_log": REDUNDANT_FULL_LOG}
    assert "full_log" not in _without_redundant_full_log(alert)


def test_the_original_alert_is_not_mutated() -> None:
    """Callers still need full_log for the cache key and the audit trail."""
    alert = {"data": ANOMALY_DATA, "full_log": REDUNDANT_FULL_LOG}
    _without_redundant_full_log(alert)
    assert alert["full_log"] == REDUNDANT_FULL_LOG


def test_a_raw_log_line_is_kept() -> None:
    """For most decoders full_log is the primary evidence, not a duplicate."""
    alert = {
        "data": {"srcip": "203.0.113.5", "dstuser": "root"},
        "full_log": "Nov 12 10:00:01 host sshd[1]: Failed password for root from 203.0.113.5",
    }
    assert "full_log" in _without_redundant_full_log(alert)


def test_json_full_log_carrying_extra_fields_is_kept() -> None:
    """Parsing as JSON is not enough; it must add nothing beyond data."""
    alert = {
        "data": ANOMALY_DATA,
        "full_log": json.dumps({"anomaly_detector": ANOMALY_DATA["anomaly_detector"], "extra": 1}),
    }
    assert "full_log" in _without_redundant_full_log(alert)


def test_alert_without_full_log_is_unchanged() -> None:
    alert = {"data": ANOMALY_DATA}
    assert _without_redundant_full_log(alert) == alert


def test_prompt_keeps_the_alert_intact_apart_from_full_log() -> None:
    """The model must still receive every field it reasons over."""
    alert = {
        "rule": {"id": "100100", "level": 9, "description": "AI Autoencoder: anomalous behaviour"},
        "agent": {"id": "000", "name": "my-server"},
        "data": ANOMALY_DATA,
        "full_log": REDUNDANT_FULL_LOG,
    }
    client = OllamaSOCClient(ollama_url="http://localhost:11434", model_name="test")
    prompt = client._build_user_prompt(alert, ["- context fragment"])

    assert "my-server-3" in prompt
    assert "journalctl" in prompt
    assert "AI Autoencoder: anomalous behaviour" in prompt
    assert "context fragment" in prompt
    # The duplicate is gone: the payload appears once, inside data.
    assert prompt.count("journalctl") == 1
