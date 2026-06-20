"""Tests for the Active Response safety controls and idempotency window."""

from __future__ import annotations

from src.responder import WazuhResponder


def test_kill_switch_suppresses_everything(tmp_path) -> None:
    kill = tmp_path / "KILL"
    kill.write_text("x")
    responder = WazuhResponder(
        dry_run=True,
        command_allowlist=["firewall-drop"],
        kill_switch_file=str(kill),
    )
    assert responder.trigger_active_response("001", "firewall-drop", []) is False


def test_command_not_in_allowlist_is_refused() -> None:
    responder = WazuhResponder(dry_run=True, command_allowlist=["firewall-drop"])
    assert responder.trigger_active_response("001", "rm-rf", []) is False


def test_dry_run_allows_without_dispatch() -> None:
    responder = WazuhResponder(dry_run=True, command_allowlist=["firewall-drop"])
    assert responder.trigger_active_response("001", "firewall-drop", []) is True


def test_idempotency_skips_repeat_real_dispatch(monkeypatch) -> None:
    clock = {"t": 0.0}
    responder = WazuhResponder(
        dry_run=False,
        command_allowlist=["firewall-drop"],
        wazuh_api_url="https://manager.example:55000",
        dedup_ttl_seconds=300,
        time_fn=lambda: clock["t"],
    )
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        responder,
        "_dispatch_via_api",
        lambda agent, command, args: calls.append((agent, command)) or True,
    )

    assert responder.trigger_active_response("001", "firewall-drop", []) is True
    # Immediate repeat is deduplicated: reported handled, but not re-dispatched.
    assert responder.trigger_active_response("001", "firewall-drop", []) is True
    assert len(calls) == 1

    # A different target is not affected by the dedup of the first one.
    assert responder.trigger_active_response("002", "firewall-drop", []) is True
    assert len(calls) == 2

    # Once the window expires, the same order dispatches again.
    clock["t"] = 301.0
    assert responder.trigger_active_response("001", "firewall-drop", []) is True
    assert len(calls) == 3


def test_failed_dispatch_is_not_remembered(monkeypatch) -> None:
    responder = WazuhResponder(
        dry_run=False,
        command_allowlist=["firewall-drop"],
        wazuh_api_url="https://manager.example:55000",
        dedup_ttl_seconds=300,
    )
    calls: list[str] = []

    def _fail(agent, command, args):
        calls.append(agent)
        return False

    monkeypatch.setattr(responder, "_dispatch_via_api", _fail)
    # Two attempts both reach dispatch because a failure must stay retryable.
    assert responder.trigger_active_response("001", "firewall-drop", []) is False
    assert responder.trigger_active_response("001", "firewall-drop", []) is False
    assert len(calls) == 2
