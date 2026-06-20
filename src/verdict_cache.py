"""Verdict cache: skip re-triaging duplicate alerts.

A SOC sees the same benign anomaly repeatedly (e.g. a known admin running the
same maintenance command on the same host). Re-running RAG retrieval and a local
CPU LLM for every identical alert is the dominant cost of the pipeline, so the
verdict is cached by a normalized alert signature and reused within a TTL.

Safety properties:

* **Behavior-preserving** — a cache hit reuses the stored verdict and the caller
  still runs the normal downstream (re-injection, active response). The cache
  only removes recomputation; it never changes a decision.
* **Conservative signature** — the real risk of a verdict cache is a *false hit*
  (a malicious alert inheriting a benign verdict). The key matches the rule,
  host, user, process and the *exact* command (whitespace-normalized only — no
  token/IP/path templating, which could collapse a benign and a malicious
  command onto one key). It is scoped to anomaly-detector alerts; anything
  without that enrichment is uncacheable (always a miss).
* **Bounded** — TTL plus LRU eviction, so the cache cannot grow without limit.
"""

from __future__ import annotations

import hashlib
import threading
import time as _time
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional, Tuple

# Cap on the command text folded into the signature, mirroring the bound used
# when the same command is embedded for RAG so a pathological log line cannot
# dominate the key.
_MAX_COMMAND_CHARS = 256

# Field separator that cannot appear in the joined values, preventing two
# different field splits from producing the same canonical string.
_SEP = "\x1f"


def _normalize_command(command: Any) -> str:
    """Collapse whitespace and truncate; deliberately *not* a semantic rewrite.

    Only trivial whitespace differences are smoothed over. Templating out IPs,
    paths or hashes is intentionally avoided: collapsing a benign and a
    malicious command onto one key would be a security failure.
    """
    collapsed = " ".join(str(command).split())
    return collapsed[:_MAX_COMMAND_CHARS]


def alert_signature(alert: Dict[str, Any]) -> Optional[str]:
    """Return a stable cache key for an alert, or ``None`` if it is uncacheable.

    Only anomaly-detector alerts carrying at least a command or a process name
    are cacheable; everything else returns ``None`` (always a cache miss) so
    sparse, weakly-identified alerts are never collapsed together.
    """
    data = alert.get("data") or {}
    anomaly = data.get("anomaly_detector") or {}
    if not isinstance(anomaly, dict):
        return None

    process = str(anomaly.get("process_name", "")).strip()
    command = _normalize_command(anomaly.get("command", ""))
    if not command and not process:
        return None

    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    host = str(anomaly.get("agent_name") or agent.get("name") or "").strip()
    user = str(anomaly.get("user", "")).strip()
    rule_id = str(rule.get("id", "")).strip()

    canonical = _SEP.join([rule_id, host, user, process, command])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class TTLCache:
    """A small thread-safe cache with per-entry TTL and LRU eviction.

    Dependency-free and self-contained so the cache logic is trivially unit
    testable with an injected clock (``time_fn``).
    """

    def __init__(
        self,
        *,
        max_entries: int = 1024,
        ttl_seconds: float = 3600.0,
        time_fn: Callable[[], float] = _time.monotonic,
    ) -> None:
        self.max_entries = max(1, int(max_entries))
        self.ttl_seconds = float(ttl_seconds)
        self._time_fn = time_fn
        self._lock = threading.Lock()
        # key -> (expires_at, value); ordered with the LRU entry at the front.
        self._store: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        """Return the value for ``key`` if present and unexpired, else ``None``."""
        now = self._time_fn()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at <= now:
                del self._store[key]
                return None
            self._store.move_to_end(key)
            return value

    def put(self, key: str, value: Any) -> None:
        """Store ``value`` under ``key`` with a fresh TTL, evicting as needed."""
        now = self._time_fn()
        with self._lock:
            self._store[key] = (now + self.ttl_seconds, value)
            self._store.move_to_end(key)
            self._evict(now)

    def _evict(self, now: float) -> None:
        """Drop expired entries, then enforce the size bound (least-recent first)."""
        expired = [key for key, (expires_at, _) in self._store.items() if expires_at <= now]
        for key in expired:
            del self._store[key]
        while len(self._store) > self.max_entries:
            self._store.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)
