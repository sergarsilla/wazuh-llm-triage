"""Autonomous SOC-L1 triage pipeline orchestrator.

Wires the components together as a producer/consumer system so that file
ingestion never blocks LLM inference:

    [ingester thread] --queue--> [triage consumer]
        watch_alerts()              RAG -> LLM -> (Active Response)

A background thread tails ``alerts.json`` and enqueues critical alerts. The
main thread drains the queue and runs each alert through RAG context retrieval,
LLM triage and, when warranted, the (dry-run) responder. A bounded queue applies
backpressure during transient Ollama/Qdrant outages: the producer blocks instead
of growing the queue until the process runs out of memory, and nothing is dropped
because the alerts stay in Wazuh's on-disk log and the tail resumes once the
consumer catches up. Per-alert failures are logged and skipped without stopping
the loop.
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
from .verdict_cache import TTLCache, alert_signature
from .wazuh_injector import WazuhVerdictInjector

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
    """Best-effort extraction of the *affected* Wazuh agent id from an alert.

    For anomaly-detector alerts the top-level ``agent`` is the manager (the
    detector injected the event with location ``anomaly_detector``), so the real
    target host lives in ``data.anomaly_detector.agent_id``. Prefer that when
    present, otherwise fall back to the standard top-level agent id.
    """
    data = alert.get("data") or {}
    anomaly = data.get("anomaly_detector") or {}
    if anomaly.get("agent_id"):
        return str(anomaly["agent_id"])
    agent = alert.get("agent") or {}
    return str(agent.get("id", "000"))


def _parse_groups(value: Any) -> "list[str] | None":
    """Parse a comma-separated string (or a list) into a list, or None if empty."""
    items = value if isinstance(value, (list, tuple)) else str(value or "").split(",")
    groups = [str(item).strip() for item in items if str(item).strip()]
    return groups or None


def _as_bool(value: Any, *, default: bool) -> bool:
    """Coerce an env-expanded string (or bool) to a bool; unknown -> ``default``.

    Used for safety-relevant toggles, so ``dry_run`` can default to True and only
    an explicit false-ish value ever enables real active response.
    """
    if isinstance(value, bool):
        return value
    text = str(value if value is not None else "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


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
            require_groups=_parse_groups(config.get("triage_rule_groups")),
            from_start=bool(config.get("read_from_start", False)),
        ):
            if stop_event.is_set():
                break
            work_queue.put(alert)
    except Exception:  # noqa: BLE001 - keep the thread's failure visible
        logger.exception("Ingester thread crashed")
    finally:
        work_queue.put(_SHUTDOWN)


def _classify(verdict: Dict[str, Any]) -> str:
    """Map an LLM verdict to an escalation category.

    Trust the LLM's risk level over its (sometimes inconsistent) false_positive
    flag: only HIGH/CRITICAL real threats e-mail (MALICIOUS); MEDIUM is a
    dashboard-only review signal (SUSPICIOUS); LOW or an explicit false positive
    is dismissed silently (FALSE_POSITIVE).
    """
    if verdict["false_positive"] or verdict["real_risk_level"] == "LOW":
        return "FALSE_POSITIVE"
    if verdict["real_risk_level"] == "MEDIUM":
        return "SUSPICIOUS"
    return "MALICIOUS"


def _process_alert(
    alert: Dict[str, Any],
    rag: QdrantRAGManager,
    llm: OllamaSOCClient,
    responder: WazuhResponder,
    verdict_injector: "WazuhVerdictInjector | None" = None,
    cache: "TTLCache | None" = None,
) -> None:
    """Run a single alert through RAG -> LLM -> (verdict re-injection, Active Response).

    A verdict cache, when supplied, short-circuits RAG + LLM for a repeat of an
    already-triaged alert. The reused verdict drives the exact same downstream
    as a fresh one, so the cache only removes recomputation, never a decision.
    """
    rule = alert.get("rule") or {}
    logger.info(
        "Triaging alert: rule.id=%s level=%s desc=%r agent=%s",
        rule.get("id"), rule.get("level"), rule.get("description"), _agent_id_of(alert),
    )

    signature = alert_signature(alert) if cache is not None else None
    verdict: "Dict[str, Any] | None" = None
    if signature is not None:
        cached = cache.get(signature)  # type: ignore[union-attr]
        if cached is not None:
            verdict = dict(cached)
            logger.info("Cache HIT (sig=%s): reusing verdict, skipping RAG+LLM", signature[:12])

    if verdict is None:
        context = rag.query_context(alert, top_k=rag.top_k)
        verdict = llm.analyze_incident(alert, context)
        if signature is not None:
            cache.put(signature, dict(verdict))  # type: ignore[union-attr]

    logger.info(
        "Verdict: false_positive=%s risk=%s active_response=%s | %s",
        verdict["false_positive"],
        verdict["real_risk_level"],
        verdict["requires_active_response"],
        verdict["technical_justification"],
    )

    # Graduated escalation: re-inject the verdict so it surfaces in the dashboard.
    # Only a confirmed HIGH/CRITICAL threat e-mails; MEDIUM is a silent review
    # signal; LOW / false positive is dismissed.
    classification = _classify(verdict)
    anomaly = (alert.get("data") or {}).get("anomaly_detector") or {}

    if verdict_injector is not None:
        verdict_injector.send_verdict(
            verdict=classification,
            risk_level=verdict["real_risk_level"],
            requires_response=verdict["requires_active_response"],
            agent_id=_agent_id_of(alert),
            rule_id=str(rule.get("id", "")),
            user=str(anomaly.get("user", "")),
            process=str(anomaly.get("process_name", "")),
            command=str(anomaly.get("command", "")),
            anomaly_score=str(anomaly.get("anomaly_score", "")),
            justification=verdict["technical_justification"],
            correlation_id=str(alert.get("id", "")),
        )

    # Active response only for a confirmed (HIGH/CRITICAL) threat.
    if classification == "MALICIOUS" and verdict["requires_active_response"]:
        # The LLM's free-text suggestion is advisory only and is never executed;
        # we dispatch a fixed, allowlisted containment command instead.
        suggested = verdict["suggested_mitigation_command"]
        if suggested:
            logger.info("LLM suggested mitigation (advisory, not executed): %s", suggested)
        responder.trigger_active_response(
            agent_id=_agent_id_of(alert),
            command=responder.default_command,
            arguments=[],
        )


def _build_work_queue(config: Dict[str, Any]) -> "queue.Queue[Any]":
    """Create the producer/consumer queue, bounded unless explicitly unlimited.

    A bounded queue applies backpressure: if the inference backends stall, the
    producer blocks on ``put`` rather than letting the queue grow until the
    process is OOM-killed. Nothing is lost — unread alerts remain in Wazuh's
    on-disk log and the tail resumes when the consumer drains. Set
    ``max_queue_size`` to 0 to restore an unbounded queue.
    """
    return queue.Queue(maxsize=int(config.get("max_queue_size", 10000)))


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

    vi_cfg = config.get("verdict_injection", {})
    verdict_injector: "WazuhVerdictInjector | None" = None
    if _as_bool(vi_cfg.get("enabled"), default=False):
        verdict_injector = WazuhVerdictInjector(
            vi_cfg.get("socket_path", "/var/ossec/queue/sockets/queue")
        )
        logger.info("Verdict re-injection enabled (socket: %s)", verdict_injector.socket_path)

    responder_cfg = config.get("responder", {})
    responder = WazuhResponder(
        dry_run=_as_bool(responder_cfg.get("dry_run"), default=True),
        command_allowlist=_parse_groups(responder_cfg.get("command_allowlist")),
        kill_switch_file=responder_cfg.get("kill_switch_file") or None,
        default_command=responder_cfg.get("default_command", "firewall-drop"),
        wazuh_api_url=responder_cfg.get("wazuh_api_url"),
        wazuh_api_user=responder_cfg.get("wazuh_api_user"),
        wazuh_api_password=responder_cfg.get("wazuh_api_password"),
        verify_ssl=_as_bool(responder_cfg.get("verify_ssl"), default=False),
    )

    vc_cfg = config.get("verdict_cache", {})
    verdict_cache: "TTLCache | None" = None
    if _as_bool(vc_cfg.get("enabled"), default=True):
        verdict_cache = TTLCache(
            max_entries=int(vc_cfg.get("max_entries", 1024)),
            ttl_seconds=float(vc_cfg.get("ttl_seconds", 3600)),
        )
        logger.info(
            "Verdict cache enabled (max_entries=%d, ttl=%.0fs)",
            verdict_cache.max_entries, verdict_cache.ttl_seconds,
        )

    work_queue: "queue.Queue[Any]" = _build_work_queue(config)
    logger.info(
        "Work queue bounded at %s (0 = unbounded)",
        work_queue.maxsize if work_queue.maxsize > 0 else "unbounded",
    )
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
                _process_alert(item, rag, llm, responder, verdict_injector, verdict_cache)
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
