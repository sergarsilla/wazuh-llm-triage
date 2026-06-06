"""Index the corporate knowledge base into Qdrant for RAG retrieval.

Reads every ``.txt`` / ``.md`` file under ``knowledge_base/``, splits each file
into paragraph-sized chunks, embeds them with the configured Ollama model
(``all-minilm``, 384 dims) and upserts them into the Qdrant collection using
cosine similarity.

Run from the project root:

    python -m data_ingest.populate_db            # uses config/app_config.json
    python data_ingest/populate_db.py            # same, path is auto-resolved
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import List

from qdrant_client.http import models as qmodels

# Allow running the file directly (python data_ingest/populate_db.py).
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import load_config  # noqa: E402
from src.rag_manager import QdrantRAGManager  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(message)s")
logger = logging.getLogger("populate_db")

KNOWLEDGE_DIR = PROJECT_ROOT / "data_ingest" / "knowledge_base"
CONFIG_PATH = PROJECT_ROOT / "config" / "app_config.json"

# Documents shorter than this many characters are kept whole; longer paragraphs
# are emitted as individual chunks.
_MIN_CHUNK_CHARS = 40


def chunk_text(text: str) -> List[str]:
    """Split a document into paragraph chunks (blank-line separated)."""
    chunks = [block.strip() for block in text.split("\n\n")]
    return [block for block in chunks if len(block) >= _MIN_CHUNK_CHARS]


def collect_documents() -> List[tuple[str, str]]:
    """Return ``(source, chunk_text)`` pairs for the knowledge base.

    Recurses into subdirectories so a gitignored ``local/`` folder can hold the
    deployer's real environment notes without committing them.
    """
    documents: List[tuple[str, str]] = []
    for path in sorted(KNOWLEDGE_DIR.rglob("*")):
        if path.suffix.lower() not in {".txt", ".md"}:
            continue
        text = path.read_text(encoding="utf-8")
        source = str(path.relative_to(KNOWLEDGE_DIR))
        for chunk in chunk_text(text):
            documents.append((source, chunk))
    return documents


def main() -> int:
    if not KNOWLEDGE_DIR.is_dir():
        logger.error("Knowledge base directory not found: %s", KNOWLEDGE_DIR)
        return 1

    config = load_config(CONFIG_PATH)
    rag = QdrantRAGManager(
        qdrant_url=config["qdrant_url"],
        ollama_url=config["ollama_url"],
        embedding_model_name=config["embedding_model_name"],
        collection_name=config["qdrant_collection"],
        embedding_dim=int(config.get("embedding_dim", 384)),
        top_k=int(config.get("rag_top_k", 3)),
        timeout=int(config.get("request_timeout_seconds", 120)),
    )

    documents = collect_documents()
    if not documents:
        logger.error("No knowledge-base documents found under %s", KNOWLEDGE_DIR)
        return 1
    logger.info("Indexing %d chunk(s) from %s", len(documents), KNOWLEDGE_DIR)

    # Recreate the collection for a clean, idempotent re-index.
    if rag.client.collection_exists(rag.collection_name):
        rag.client.delete_collection(rag.collection_name)
    rag.ensure_collection()

    points: List[qmodels.PointStruct] = []
    for idx, (source, chunk) in enumerate(documents):
        vector = rag.generate_vector(chunk)
        points.append(
            qmodels.PointStruct(
                id=idx,
                vector=vector,
                payload={"text": chunk, "source": source},
            )
        )
        logger.info("  [%d/%d] embedded chunk from %s", idx + 1, len(documents), source)

    rag.client.upsert(collection_name=rag.collection_name, points=points)
    logger.info("Done. Indexed %d chunk(s) into collection '%s'.", len(points), rag.collection_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
