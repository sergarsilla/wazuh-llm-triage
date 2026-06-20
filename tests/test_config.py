"""Tests for the ${VAR:-default} environment expansion in the config loader."""

from __future__ import annotations

import json

import pytest

from src.config import load_config


def _write(tmp_path, payload: dict) -> str:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_default_is_used_when_variable_is_unset(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("TRIAGE_TEST_VAR", raising=False)
    path = _write(tmp_path, {"value": "${TRIAGE_TEST_VAR:-fallback}"})
    assert load_config(path)["value"] == "fallback"


def test_environment_overrides_the_default(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("TRIAGE_TEST_VAR", "from-env")
    path = _write(tmp_path, {"value": "${TRIAGE_TEST_VAR:-fallback}"})
    assert load_config(path)["value"] == "from-env"


def test_nested_and_empty_defaults_resolve(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("TRIAGE_EMPTY", raising=False)
    path = _write(tmp_path, {"outer": {"inner": "${TRIAGE_EMPTY:-}"}})
    assert load_config(path)["outer"]["inner"] == ""


def test_missing_file_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "does_not_exist.json"))
