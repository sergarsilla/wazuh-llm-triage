"""Replay sample Wazuh alerts into the watched alerts file (simulation mode).

This lets you exercise the full pipeline on a workstation that is only a Wazuh
*agent* (not a manager), without a live ``alerts.json``. It appends each alert
from ``sample_alerts.jsonl`` to the ``wazuh_alerts_path`` configured in
``config/app_config.json``, one line at a time, so the running pipeline picks
them up exactly as it would real-time manager output.

Typical usage (two terminals):

    # Terminal 1 - start the pipeline
    python -m src.pipeline

    # Terminal 2 - feed alerts
    python data_ingest/simulate_alerts.py --interval 3 --reset
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import load_config  # noqa: E402

CONFIG_PATH = PROJECT_ROOT / "config" / "app_config.json"
SAMPLE_PATH = PROJECT_ROOT / "data_ingest" / "sample_alerts.jsonl"


def load_alerts_path() -> Path:
    config = load_config(CONFIG_PATH)
    path = Path(config["wazuh_alerts_path"])
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Feed sample alerts into the watched file.")
    parser.add_argument("--interval", type=float, default=3.0, help="Seconds between alerts.")
    parser.add_argument("--reset", action="store_true", help="Truncate the target file first.")
    args = parser.parse_args()

    target = load_alerts_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    if args.reset and target.exists():
        target.unlink()
    # Ensure the file exists so the pipeline's tail can attach to it.
    target.touch(exist_ok=True)

    lines = [ln for ln in SAMPLE_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
    print(f"Feeding {len(lines)} alert(s) into {target} every {args.interval}s")

    for i, line in enumerate(lines, start=1):
        with target.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
        rule = json.loads(line).get("rule", {})
        print(f"  -> [{i}/{len(lines)}] level={rule.get('level')} {rule.get('description')!r}")
        if i < len(lines):
            time.sleep(args.interval)

    print("All sample alerts fed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
