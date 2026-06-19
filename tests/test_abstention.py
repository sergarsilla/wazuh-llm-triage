"""Tests for verdict confidence parsing and the abstention routing rule."""

from __future__ import annotations

from src.llm_client import OllamaSOCClient
from src.pipeline import _apply_abstention


def test_validate_defaults_confidence_to_full_when_missing() -> None:
    verdict = OllamaSOCClient._validate({"real_risk_level": "HIGH"})
    assert verdict["confidence"] == 1.0


def test_validate_clamps_confidence_into_unit_range() -> None:
    assert OllamaSOCClient._validate({"confidence": 1.8})["confidence"] == 1.0
    assert OllamaSOCClient._validate({"confidence": -0.4})["confidence"] == 0.0


def test_validate_handles_non_numeric_confidence() -> None:
    assert OllamaSOCClient._validate({"confidence": "n/a"})["confidence"] == 1.0


def test_abstention_downgrades_low_confidence_to_review() -> None:
    # Below the threshold, neither auto-dismiss nor auto-escalate: review it.
    assert _apply_abstention("MALICIOUS", 0.3, 0.5) == "SUSPICIOUS"
    assert _apply_abstention("FALSE_POSITIVE", 0.3, 0.5) == "SUSPICIOUS"


def test_abstention_keeps_confident_verdicts() -> None:
    assert _apply_abstention("MALICIOUS", 0.9, 0.5) == "MALICIOUS"
    assert _apply_abstention("FALSE_POSITIVE", 0.9, 0.5) == "FALSE_POSITIVE"


def test_abstention_is_disabled_at_zero_threshold() -> None:
    assert _apply_abstention("MALICIOUS", 0.0, 0.0) == "MALICIOUS"
