"""Retrieval-Augmented Generation context provider backed by Qdrant.

Embeddings are produced by a local Ollama model (``all-minilm``, 384 dims) and
stored/searched in a Qdrant collection using cosine similarity:

    similarity(A, B) = (A . B) / (||A|| * ||B||)

``query_context`` turns the operationally relevant fields of a Wazuh alert
(source IP, hostname, rule id/description) into a search string, embeds it and
returns the ``top_k`` most semantically similar knowledge-base fragments.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

import requests
from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

logger = logging.getLogger(__name__)

# Fixed embedding dimensionality mandated by the architecture contract.
EMBEDDING_DIM = 384

# Upper bound on the (attacker-influenced) anomaly command text folded into the
# embedding search string, so a pathological log line cannot dominate retrieval.
_MAX_COMMAND_CHARS = 256


class QdrantRAGManager:
    """Generates embeddings via Ollama and retrieves context from Qdrant."""

    def __init__(
        self,
        qdrant_url: str,
        ollama_url: str,
        embedding_model_name: str,
        collection_name: str,
        *,
        embedding_dim: int = EMBEDDING_DIM,
        top_k: int = 3,
        timeout: int = 120,
    ) -> None:
        self.ollama_url = ollama_url.rstrip("/")
        self.embedding_model_name = embedding_model_name
        self.collection_name = collection_name
        self.embedding_dim = embedding_dim
        self.top_k = top_k
        self.timeout = timeout
        self.client = QdrantClient(url=qdrant_url, timeout=timeout)

    # ------------------------------------------------------------------ #
    # Collection management
    # ------------------------------------------------------------------ #
    def ensure_collection(self) -> None:
        """Create the collection with a cosine-distance 384-d space if absent."""
        if self.client.collection_exists(self.collection_name):
            return
        logger.info("Creating Qdrant collection '%s' (dim=%d, Cosine)", self.collection_name, self.embedding_dim)
        self.client.create_collection(
            collection_name=self.collection_name,
            vectors_config=qmodels.VectorParams(
                size=self.embedding_dim,
                distance=qmodels.Distance.COSINE,
            ),
        )

    # ------------------------------------------------------------------ #
    # Embeddings
    # ------------------------------------------------------------------ #
    def generate_vector(self, text: str) -> List[float]:
        """Embed ``text`` with the configured Ollama model and return the vector.

        Raises:
            requests.HTTPError: if the Ollama API returns a non-2xx response.
            ValueError: if the returned vector does not match ``embedding_dim``.
        """
        response = requests.post(
            f"{self.ollama_url}/api/embed",
            json={"model": self.embedding_model_name, "input": text},
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        # /api/embed returns a batch under "embeddings"; we send a single input.
        embeddings = payload.get("embeddings") or []
        if not embeddings:
            raise ValueError("Ollama returned no embeddings for the requested text")
        vector = embeddings[0]
        if len(vector) != self.embedding_dim:
            raise ValueError(
                f"Embedding dimension mismatch: expected {self.embedding_dim}, got {len(vector)}"
            )
        return vector

    # ------------------------------------------------------------------ #
    # Context retrieval
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_search_query(alert_data: Dict[str, Any]) -> str:
        """Flatten the salient Wazuh alert fields into one search string.

        Also handles anomaly-detector alerts, whose context (user, process,
        command) lives under ``data.anomaly_detector`` rather than the usual
        top-level fields.
        """
        rule = alert_data.get("rule") or {}
        data = alert_data.get("data") or {}
        agent = alert_data.get("agent") or {}
        anomaly = data.get("anomaly_detector") or {}

        parts: List[str] = []

        # Injected anomaly alerts carry the manager as top-level agent; prefer
        # the affected host from the payload.
        host = anomaly.get("agent_name") or agent.get("name")
        if host:
            parts.append(f"Host: {host}")

        # Enrichment fields (user/process/command) carry the behavioural signal.
        if anomaly:
            parts.append("Anomalous administrative command flagged by ML detector")
            if anomaly.get("user"):
                parts.append(f"User: {anomaly['user']}")
            if anomaly.get("process_name"):
                parts.append(f"Process: {anomaly['process_name']}")
            if anomaly.get("command"):
                command = str(anomaly["command"])[:_MAX_COMMAND_CHARS]
                parts.append(f"Command: {command}")

        # Wazuh stores the source IP either at data.srcip or at the top level.
        src_ip = data.get("srcip") or alert_data.get("srcip")
        if src_ip:
            parts.append(f"Source IP: {src_ip}")
        if data.get("dstuser"):
            parts.append(f"Target user: {data['dstuser']}")
        if rule.get("id"):
            parts.append(f"Rule {rule['id']}")
        if rule.get("description"):
            parts.append(str(rule["description"]))
        if rule.get("groups"):
            parts.append("Groups: " + ", ".join(map(str, rule["groups"])))

        # Fall back to the full description if nothing else is present.
        return " | ".join(parts) if parts else json_compact(alert_data)

    def query_context(self, alert_data: Dict[str, Any], top_k: int = 3) -> List[str]:
        """Return up to ``top_k`` knowledge-base fragments relevant to the alert.

        The metadata extracted from the alert is embedded and used to perform a
        cosine-similarity search against the corporate knowledge collection.
        """
        search_string = self._build_search_query(alert_data)
        logger.debug("RAG search string: %s", search_string)

        query_vector = self.generate_vector(search_string)
        result = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vector,
            limit=top_k or self.top_k,
            with_payload=True,
        )

        fragments: List[str] = []
        for point in result.points:
            payload = point.payload or {}
            text = payload.get("text")
            if text:
                fragments.append(str(text))
        logger.info("Retrieved %d context fragment(s) from Qdrant", len(fragments))
        return fragments


def json_compact(obj: Any) -> str:
    """Compact JSON serialisation used as a last-resort search string."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
