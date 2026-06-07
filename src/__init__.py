"""SOC-L1 intelligent triage middleware.

This package wires together a real-time Wazuh alert ingester, a Qdrant-backed
RAG context provider, a local Ollama LLM triage client, and a (dry-run capable)
Wazuh Active Response module into a single autonomous pipeline.
"""

__all__ = [
    "ingester",
    "rag_manager",
    "llm_client",
    "responder",
    "pipeline",
]
