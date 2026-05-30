"""Real-time, non-blocking ingester for the Wazuh ``alerts.json`` file.

Wazuh writes one JSON document per line to ``alerts.json``. This module tails
that file (``tail -f`` semantics) without blocking, deserialises each line and
yields only the alerts whose ``rule.level`` meets or exceeds a configured
severity threshold. Log rotation is handled by watching the file inode and
size so the stream survives ``logrotate`` truncation/rename cycles.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Generator, Optional

logger = logging.getLogger(__name__)

# Seconds to wait between read attempts when the file has no new data, and
# between retries while waiting for the alerts file to appear.
_DEFAULT_POLL_INTERVAL = 0.5


def _extract_rule_level(alert: Dict[str, Any]) -> Optional[int]:
    """Return ``rule.level`` as an int, or ``None`` if it is missing/invalid."""
    rule = alert.get("rule")
    if not isinstance(rule, dict):
        return None
    level = rule.get("level")
    try:
        # Wazuh emits the level as an int, but tolerate string encodings too.
        return int(level)
    except (TypeError, ValueError):
        return None


def _open_at_offset(file_path: str, from_start: bool):
    """Open ``file_path`` and return ``(handle, inode)`` positioned for reading.

    When ``from_start`` is False the handle is seeked to EOF so only alerts
    appended after start-up are streamed (true real-time monitoring).
    """
    handle = open(file_path, "r", encoding="utf-8", errors="replace")
    inode = os.fstat(handle.fileno()).st_ino
    if not from_start:
        handle.seek(0, os.SEEK_END)
    return handle, inode


def _rotated(file_path: str, open_inode: int, current_offset: int) -> bool:
    """Detect rotation/truncation of the file currently being tailed.

    Returns True when the path now points at a different inode (rename + new
    file) or when the on-disk file is shorter than our read offset (in-place
    truncation), in which case the caller must reopen from the start.
    """
    try:
        stat = os.stat(file_path)
    except FileNotFoundError:
        # The file vanished mid-rotation; treat as rotated and let the caller
        # wait for the replacement to appear.
        return True
    return stat.st_ino != open_inode or stat.st_size < current_offset


def watch_alerts(
    file_path: str,
    min_level: int,
    *,
    from_start: bool = False,
    poll_interval: float = _DEFAULT_POLL_INTERVAL,
) -> Generator[Dict[str, Any], None, None]:
    """Tail ``file_path`` and yield critical Wazuh alerts as dictionaries.

    Args:
        file_path: Path to the Wazuh ``alerts.json`` file.
        min_level: Minimum ``rule.level`` required for an alert to be yielded.
        from_start: If True, replay existing lines before tailing; otherwise
            start at EOF and only emit newly appended alerts.
        poll_interval: Idle sleep, in seconds, between read attempts.

    Yields:
        The deserialised alert dictionary for every line whose ``rule.level``
        is greater than or equal to ``min_level``.
    """
    # Outer loop owns (re)opening the file across rotations and start-up gaps.
    while True:
        if not os.path.exists(file_path):
            logger.warning("Alerts file %s not found; waiting for it to appear", file_path)
            while not os.path.exists(file_path):
                time.sleep(poll_interval)

        handle, inode = _open_at_offset(file_path, from_start)
        logger.info("Tailing alerts file %s (inode=%s, from_start=%s)", file_path, inode, from_start)

        # Accumulates bytes for a line that has not been fully flushed yet.
        line_buffer = ""
        try:
            while True:
                chunk = handle.readline()
                if chunk:
                    line_buffer += chunk
                    if not line_buffer.endswith("\n"):
                        # Partial line: wait for the writer to flush the rest.
                        continue
                    raw_line = line_buffer.strip()
                    line_buffer = ""
                    if not raw_line:
                        continue

                    try:
                        alert = json.loads(raw_line)
                    except json.JSONDecodeError:
                        logger.warning("Skipping malformed JSON line in %s", file_path)
                        continue

                    level = _extract_rule_level(alert)
                    if level is None:
                        continue
                    if level >= min_level:
                        yield alert
                    continue

                # No new data: check for rotation, otherwise idle.
                if _rotated(file_path, inode, handle.tell()):
                    logger.info("Rotation detected on %s; reopening", file_path)
                    break
                time.sleep(poll_interval)
        finally:
            handle.close()
        # After the file is rotated for the first time we always want to read
        # the replacement from its beginning.
        from_start = True
