"""Tests for config env-expansion and the pipeline's value-coercion helpers.

These guard the safety-relevant defaults: ``dry_run`` must default to True, an
empty score threshold must mean "disabled" (not crash), and the affected-agent
extraction must prefer the anomaly payload's target over the manager.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.config import load_config
from src.pipeline import _agent_id_of, _as_bool, _as_float_or_none, _parse_groups


def _write_config(tmp_path: Path, payload: dict) -> str:
    path = tmp_path / "app_config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_config_resolves_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_URL", "http://10.0.0.9:11434")
    path = _write_config(tmp_path, {"ollama_url": "${OLLAMA_URL:-http://localhost:11434}"})
    assert load_config(path)["ollama_url"] == "http://10.0.0.9:11434"


def test_config_uses_default_when_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    path = _write_config(tmp_path, {"ollama_url": "${OLLAMA_URL:-http://localhost:11434}"})
    assert load_config(path)["ollama_url"] == "http://localhost:11434"


def test_config_empty_default_resolves_to_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RAG_SCORE_THRESHOLD", raising=False)
    path = _write_config(tmp_path, {"rag_score_threshold": "${RAG_SCORE_THRESHOLD:-}"})
    assert load_config(path)["rag_score_threshold"] == ""


def test_config_unknown_var_without_default_is_left_intact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A misconfiguration must surface loudly, not silently empty the value."""
    monkeypatch.delenv("MISSING", raising=False)
    path = _write_config(tmp_path, {"x": "${MISSING}"})
    assert load_config(path)["x"] == "${MISSING}"


def test_config_expands_nested_structures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("P", "secret")
    path = _write_config(tmp_path, {"responder": {"pw": "${P:-x}", "list": ["${P:-x}"]}})
    config = load_config(path)
    assert config["responder"]["pw"] == "secret"
    assert config["responder"]["list"] == ["secret"]


def test_load_config_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "nope.json"))


@pytest.mark.parametrize(
    ("value", "default", "expected"),
    [
        ("true", False, True),
        ("YES", False, True),
        ("on", False, True),
        ("false", True, False),
        ("0", True, False),
        (True, False, True),
        ("garbage", True, True),   # unknown -> default
        ("garbage", False, False),
        ("", True, True),
    ],
)
def test_as_bool(value, default, expected) -> None:
    assert _as_bool(value, default=default) is expected


def test_as_bool_dry_run_defaults_safe() -> None:
    """An unparseable dry_run value must keep active response suppressed."""
    assert _as_bool(None, default=True) is True


@pytest.mark.parametrize(
    ("value", "expected"),
    [("", None), (None, None), ("0.7", 0.7), ("  0.5 ", 0.5), ("abc", None)],
)
def test_as_float_or_none(value, expected) -> None:
    assert _as_float_or_none(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("firewall-drop,disable-account", ["firewall-drop", "disable-account"]),
        (["a", " b ", ""], ["a", "b"]),
        ("", None),
        (None, None),
        ("  ", None),
    ],
)
def test_parse_groups(value, expected) -> None:
    assert _parse_groups(value) == expected


def test_agent_id_prefers_anomaly_target_over_manager() -> None:
    """Anomaly alerts carry the manager as top-level agent; the real target host
    lives in the payload and must win, or containment would hit the manager."""
    alert = {
        "agent": {"id": "000"},
        "data": {"anomaly_detector": {"agent_id": "002"}},
    }
    assert _agent_id_of(alert) == "002"


def test_agent_id_falls_back_to_top_level() -> None:
    assert _agent_id_of({"agent": {"id": "005"}}) == "005"
    assert _agent_id_of({}) == "000"
