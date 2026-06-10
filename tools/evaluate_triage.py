"""Measure the triage model against a hand-labelled alert set.

This is the regression harness you run *before trusting a model in production*
(and after any prompt/model/knowledge-base change). It feeds each alert in
``data_ingest/labeled_alerts.jsonl`` through the real RAG + LLM + classification
path and compares the resulting escalation category against the label a human
analyst assigned, then prints a confusion matrix and the metrics that actually
matter for a SOC.

Unlike the unit tests (which are offline and deterministic), this tool needs a
live Ollama and Qdrant — it is exercising the model itself, not the code. Index
the knowledge base first (``python data_ingest/populate_db.py``).

    python tools/evaluate_triage.py
    LLM_MODEL_NAME=qwen2.5:7b-instruct python tools/evaluate_triage.py

The process exits non-zero if any *critical miss* occurs (a labelled-MALICIOUS
alert that the model would have dismissed as FALSE_POSITIVE), so it can gate a
model rollout in CI. A critical miss is the one error class that means a real
intrusion goes unseen, so it is weighted above raw accuracy.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import load_config  # noqa: E402
from src.llm_client import OllamaSOCClient  # noqa: E402
from src.pipeline import _as_float_or_none, _classify  # noqa: E402
from src.rag_manager import QdrantRAGManager  # noqa: E402

CONFIG_PATH = PROJECT_ROOT / "config" / "app_config.json"
LABELLED_PATH = PROJECT_ROOT / "data_ingest" / "labeled_alerts.jsonl"

CATEGORIES = ("MALICIOUS", "SUSPICIOUS", "FALSE_POSITIVE")


def load_labelled(path: Path) -> List[Dict[str, Any]]:
    """Read the labelled alert set; each line is ``{expected, alert}``."""
    cases: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            cases.append(json.loads(line))
    return cases


def _build_clients(config: Dict[str, Any]) -> "tuple[QdrantRAGManager, OllamaSOCClient]":
    timeout = int(config.get("request_timeout_seconds", 120))
    rag = QdrantRAGManager(
        qdrant_url=config["qdrant_url"],
        ollama_url=config["ollama_url"],
        embedding_model_name=config["embedding_model_name"],
        collection_name=config["qdrant_collection"],
        embedding_dim=int(config.get("embedding_dim", 384)),
        top_k=int(config.get("rag_top_k", 3)),
        score_threshold=_as_float_or_none(config.get("rag_score_threshold")),
        timeout=timeout,
    )
    llm = OllamaSOCClient(
        ollama_url=config["ollama_url"],
        model_name=config["llm_model_name"],
        timeout=timeout,
    )
    return rag, llm


def _print_confusion(matrix: Dict[str, Dict[str, int]]) -> None:
    """Render expected (rows) vs predicted (columns) as a small table."""
    width = 16
    header = "expected \\ predicted".ljust(width) + "".join(c.ljust(width) for c in CATEGORIES)
    print(header)
    for expected in CATEGORIES:
        row = expected.ljust(width)
        for predicted in CATEGORIES:
            row += str(matrix[expected][predicted]).ljust(width)
        print(row)


def evaluate(model_override: "str | None" = None) -> int:
    """Run the labelled set through the live pipeline and report. Returns an exit code."""
    config = load_config(CONFIG_PATH)
    if model_override:
        config["llm_model_name"] = model_override
    rag, llm = _build_clients(config)

    cases = load_labelled(LABELLED_PATH)
    if not cases:
        print(f"No labelled cases found in {LABELLED_PATH}", file=sys.stderr)
        return 2

    print(f"Evaluating model '{config['llm_model_name']}' on {len(cases)} labelled alert(s)\n")

    matrix = {row: {col: 0 for col in CATEGORIES} for row in CATEGORIES}
    correct = 0
    critical_misses: List[Dict[str, Any]] = []

    for index, case in enumerate(cases, start=1):
        alert = case["alert"]
        expected = case["expected"]["classification"]
        context = rag.query_context(alert, top_k=rag.top_k)
        verdict = llm.analyze_incident(alert, context)
        predicted = _classify(verdict)

        matrix[expected][predicted] += 1
        is_correct = predicted == expected
        correct += int(is_correct)
        is_critical = expected == "MALICIOUS" and predicted == "FALSE_POSITIVE"
        if is_critical:
            critical_misses.append({"case": case, "verdict": verdict})

        flag = "ok " if is_correct else ("MISS!" if is_critical else "diff ")
        rule = alert.get("rule") or {}
        print(
            f"[{index:>2}/{len(cases)}] {flag} expected={expected:<15} "
            f"predicted={predicted:<15} risk={verdict['real_risk_level']:<8} "
            f"fp={str(verdict['false_positive']):<5} :: {rule.get('description', '')[:70]}"
        )

    total = len(cases)
    print("\nConfusion matrix:")
    _print_confusion(matrix)
    print(f"\nAccuracy: {correct}/{total} = {correct / total:.1%}")
    print(f"Critical misses (MALICIOUS dismissed as FALSE_POSITIVE): {len(critical_misses)}")
    for miss in critical_misses:
        alert = miss["case"]["alert"]
        anomaly = (alert.get("data") or {}).get("anomaly_detector") or {}
        print(
            f"  - cmd={anomaly.get('command', alert.get('full_log', ''))!r} "
            f"-> {miss['verdict']['technical_justification'][:120]}"
        )

    # A single critical miss fails the run: better a loud red gate than a
    # silently under-performing model promoted to production.
    return 1 if critical_misses else 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the triage model on labelled alerts.")
    parser.add_argument(
        "--model",
        default=None,
        help="Override LLM_MODEL_NAME for this run (e.g. qwen2.5:7b-instruct).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(evaluate(_parse_args().model))
