"""Tests for the escalation logic — the safety-critical core of the pipeline.

``_classify`` decides whether an alert e-mails the team, sits in the dashboard,
or is dismissed silently. The single most dangerous failure mode is a real
threat being silently dropped, so these tests pin down that the risk level is
authoritative and the ``false_positive`` flag can never silence HIGH/CRITICAL.
"""

from __future__ import annotations

import pytest

from src.pipeline import _classify, _is_inconsistent


def verdict(
    *,
    risk: str,
    false_positive: bool = False,
    requires_response: bool = False,
) -> dict:
    """Build a minimal, schema-shaped verdict for the classifier under test."""
    return {
        "false_positive": false_positive,
        "real_risk_level": risk,
        "technical_justification": "test",
        "requires_active_response": requires_response,
        "suggested_mitigation_command": "",
    }


@pytest.mark.parametrize("risk", ["HIGH", "CRITICAL"])
def test_serious_risk_always_escalates(risk: str) -> None:
    assert _classify(verdict(risk=risk)) == "MALICIOUS"


@pytest.mark.parametrize("risk", ["HIGH", "CRITICAL"])
def test_false_positive_flag_cannot_silence_serious_risk(risk: str) -> None:
    """The regression guard: a HIGH/CRITICAL verdict the model also marked as a
    false positive must still escalate. This is the bug the change fixed — a
    model slip used to turn a real intrusion into a level-3 silent record."""
    assert _classify(verdict(risk=risk, false_positive=True)) == "MALICIOUS"


def test_medium_is_a_review_signal() -> None:
    assert _classify(verdict(risk="MEDIUM")) == "SUSPICIOUS"


def test_medium_flagged_false_positive_is_dismissed() -> None:
    """MEDIUM is inconclusive, so the model's FP call is honoured at that level."""
    assert _classify(verdict(risk="MEDIUM", false_positive=True)) == "FALSE_POSITIVE"


@pytest.mark.parametrize("false_positive", [True, False])
def test_low_risk_is_dismissed(false_positive: bool) -> None:
    assert _classify(verdict(risk="LOW", false_positive=false_positive)) == "FALSE_POSITIVE"


@pytest.mark.parametrize(
    ("risk", "false_positive", "expected"),
    [
        ("CRITICAL", True, True),
        ("HIGH", True, True),
        ("CRITICAL", False, False),
        ("MEDIUM", True, False),
        ("LOW", True, False),
    ],
)
def test_inconsistency_detection(risk: str, false_positive: bool, expected: bool) -> None:
    """Only a serious risk paired with the FP flag counts as inconsistent."""
    assert _is_inconsistent(verdict(risk=risk, false_positive=false_positive)) is expected


def test_every_risk_level_maps_to_a_valid_category() -> None:
    """No risk level may fall through to an undefined category."""
    valid = {"MALICIOUS", "SUSPICIOUS", "FALSE_POSITIVE"}
    for risk in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        for fp in (True, False):
            assert _classify(verdict(risk=risk, false_positive=fp)) in valid
