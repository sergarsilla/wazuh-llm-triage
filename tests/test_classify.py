"""Tests for verdict classification and agent-id resolution."""

from __future__ import annotations

from src.pipeline import _agent_id_of, _classify


def _verdict(risk: str, *, false_positive: bool = False) -> dict:
    return {"false_positive": false_positive, "real_risk_level": risk}


def test_false_positive_flag_and_low_risk_are_dismissed() -> None:
    assert _classify(_verdict("LOW")) == "FALSE_POSITIVE"
    # An explicit false_positive overrides even a high risk level.
    assert _classify(_verdict("CRITICAL", false_positive=True)) == "FALSE_POSITIVE"


def test_medium_risk_is_suspicious() -> None:
    assert _classify(_verdict("MEDIUM")) == "SUSPICIOUS"


def test_high_and_critical_are_malicious() -> None:
    assert _classify(_verdict("HIGH")) == "MALICIOUS"
    assert _classify(_verdict("CRITICAL")) == "MALICIOUS"


def test_agent_id_prefers_the_anomaly_target_over_the_manager() -> None:
    alert = {"data": {"anomaly_detector": {"agent_id": "007"}}, "agent": {"id": "000"}}
    assert _agent_id_of(alert) == "007"


def test_agent_id_falls_back_to_top_level_then_default() -> None:
    assert _agent_id_of({"agent": {"id": "123"}}) == "123"
    assert _agent_id_of({}) == "000"
