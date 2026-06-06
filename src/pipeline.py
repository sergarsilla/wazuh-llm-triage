"""Autonomous SOC-L1 triage pipeline orchestrator.

Wires the components together as a producer/consumer system so that file
ingestion never blocks LLM inference:

    [ingester thread] --queue--> [triage consumer]
        watch_alerts()              RAG -> LLM -> (Active Response)

A background thread tails ``alerts.json`` and enqueues critical alerts. The
main thread drains the queue and runs each alert through RAG context retrieval,
LLM triage and, when warranted, the (dry-run) responder. An unbounded queue
buffers alerts during transient Ollama/Qdrant outages so forensic telemetry is
never dropped. Per-alert failures are logged and skipped without stopping the
loop.
"""

from __future__ import annotations

import logging
import queue
import sys
import threading
from typing import Any, Dict

from .config import load_config
from .ingester import watch_alerts
from .llm_client import OllamaSOCClient
from .rag_manager import QdrantRAGManager
from .responder import WazuhResponder

logger = logging.getLogger(__name__)

# Sentinel pushed onto the queue to unblock the consumer on shutdown.
_SHUTDOWN = object()


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _agent_id_of(alert: Dict[str, Any]) -> str:
    """Best-effort extraction of the Wazuh agent id from an alert."""
    agent = alert.get("agent") or {}
    return str(agent.get("id", "000"))


def _ingest_loop(
    config: Dict[str, Any],
    work_queue: "queue.Queue[Any]",
    stop_event: threading.Event,
) -> None:
    """Producer: tail the alerts file and enqueue critical alerts."""
    try:
        for alert in watch_alerts(
            config["wazuh_alerts_path"],
            int(config["min_alert_level"]),
            from_start=bool(config.get("read_from_start", False)),
        ):
            if stop_event.is_set():
                break
            work_queue.put(alert)
    except Exception:  # noqa: BLE001 - keep the thread's failure visible
        logger.exception("Ingester thread crashed")
    finally:
        work_queue.put(_SHUTDOWN)


def _process_alert(
    alert: Dict[str, Any],
    rag: QdrantRAGManager,
    llm: OllamaSOCClient,
    responder: WazuhResponder,
) -> None:
    """Run a single alert through RAG -> LLM -> Active Response."""
    rule = alert.get("rule") or {}
    logger.info(
        "Triaging alert: rule.id=%s level=%s desc=%r agent=%s",
        rule.get("id"), rule.get("level"), rule.get("description"), _agent_id_of(alert),
    )

    context = rag.query_context(alert, top_k=rag.top_k)
    verdict = llm.analyze_incident(alert, context)

    logger.info(
        "Verdict: falso_positivo=%s riesgo=%s respuesta_activa=%s | %s",
        verdict["falso_positivo"],
        verdict["nivel_riesgo_real"],
        verdict["requiere_respuesta_activa"],
        verdict["justificacion_tecnica"],
    )

    if verdict["requiere_respuesta_activa"] and not verdict["falso_positivo"]:
        command = verdict["comando_mitigacion_sugerido"] or "firewall-drop"
        responder.trigger_active_response(
            agent_id=_agent_id_of(alert),
            command=command,
            arguments=[],
        )


def start_soc_pipeline(config_path: str = "config/app_config.json") -> None:
    """Start the autonomous triage loop using the given configuration file."""
    _setup_logging()
    config = load_config(config_path)
    logger.info("Starting SOC-L1 triage pipeline (config: %s)", config_path)

    timeout = int(config.get("request_timeout_seconds", 120))
    rag = QdrantRAGManager(
        qdrant_url=config["qdrant_url"],
        ollama_url=config["ollama_url"],
        embedding_model_name=config["embedding_model_name"],
        collection_name=config["qdrant_collection"],
        embedding_dim=int(config.get("embedding_dim", 384)),
        top_k=int(config.get("rag_top_k", 3)),
        timeout=timeout,
    )
    rag.ensure_collection()

    llm = OllamaSOCClient(
        ollama_url=config["ollama_url"],
        model_name=config["llm_model_name"],
        timeout=timeout,
    )

    responder_cfg = config.get("responder", {})
    responder = WazuhResponder(
        dry_run=bool(responder_cfg.get("dry_run", True)),
        wazuh_api_url=responder_cfg.get("wazuh_api_url"),
        wazuh_api_user=responder_cfg.get("wazuh_api_user"),
        wazuh_api_password=responder_cfg.get("wazuh_api_password"),
        verify_ssl=bool(responder_cfg.get("verify_ssl", False)),
    )

    work_queue: "queue.Queue[Any]" = queue.Queue()
    stop_event = threading.Event()
    producer = threading.Thread(
        target=_ingest_loop,
        args=(config, work_queue, stop_event),
        name="ingester",
        daemon=True,
    )
    producer.start()
    logger.info(
        "Watching %s for alerts with rule.level >= %s",
        config["wazuh_alerts_path"], config["min_alert_level"],
    )

    # Consumer loop (main thread).
    try:
        while True:
            item = work_queue.get()
            if item is _SHUTDOWN:
                logger.info("Shutdown sentinel received; stopping consumer")
                break
            try:
                _process_alert(item, rag, llm, responder)
            except Exception:  # noqa: BLE001 - one bad alert must not kill the loop
                logger.exception("Failed to process alert; continuing")
            finally:
                work_queue.task_done()
    except KeyboardInterrupt:
        logger.info("Interrupted by user; shutting down")
    finally:
        stop_event.set()


if __name__ == "__main__":
    cfg = sys.argv[1] if len(sys.argv) > 1 else "config/app_config.json"
    start_soc_pipeline(cfg)
