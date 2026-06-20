"""Pipeline-level tests: the verdict cache skips RAG+LLM yet preserves downstream."""

from __future__ import annotations

from src import pipeline
from src.verdict_cache import TTLCache


class _StubRAG:
    top_k = 3

    def __init__(self) -> None:
        self.calls = 0

    def query_context(self, alert, top_k=3):
        self.calls += 1
        return ["ctx"]


class _StubLLM:
    def __init__(self) -> None:
        self.calls = 0

    def analyze_incident(self, alert, context):
        self.calls += 1
        return {
            "false_positive": False,
            "real_risk_level": "MEDIUM",
            "technical_justification": "stub",
            "requires_active_response": False,
            "suggested_mitigation_command": "",
        }


class _StubResponder:
    default_command = "firewall-drop"

    def trigger_active_response(self, **kwargs):
        return True


class _RecordingInjector:
    def __init__(self) -> None:
        self.calls = 0

    def send_verdict(self, **kwargs):
        self.calls += 1
        return True


def _anomaly_alert(command: str = "docker ps -a") -> dict:
    return {
        "rule": {"id": "100100", "level": 12, "groups": ["anomaly_detector"]},
        "agent": {"id": "000", "name": "wazuh-manager"},
        "data": {
            "anomaly_detector": {
                "agent_id": "002",
                "agent_name": "app-host-02",
                "process_name": "docker",
                "user": "ubuntu",
                "command": command,
            }
        },
    }


def test_repeat_alert_skips_rag_and_llm_but_still_injects():
    rag, llm, responder, injector = _StubRAG(), _StubLLM(), _StubResponder(), _RecordingInjector()
    cache = TTLCache()
    alert = _anomaly_alert()

    pipeline._process_alert(alert, rag, llm, responder, injector, cache)
    pipeline._process_alert(alert, rag, llm, responder, injector, cache)

    assert llm.calls == 1  # second occurrence served from cache
    assert rag.calls == 1
    assert injector.calls == 2  # downstream is preserved on the cache hit


def test_distinct_alerts_each_invoke_llm():
    rag, llm, responder = _StubRAG(), _StubLLM(), _StubResponder()
    cache = TTLCache()

    pipeline._process_alert(_anomaly_alert("docker ps -a"), rag, llm, responder, None, cache)
    pipeline._process_alert(_anomaly_alert("rm -rf /tmp/x"), rag, llm, responder, None, cache)

    assert llm.calls == 2


def test_no_cache_always_invokes_llm():
    rag, llm, responder = _StubRAG(), _StubLLM(), _StubResponder()
    alert = _anomaly_alert()

    pipeline._process_alert(alert, rag, llm, responder, None, None)
    pipeline._process_alert(alert, rag, llm, responder, None, None)

    assert llm.calls == 2
