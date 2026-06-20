"""Wazuh Active Response module.

Issues containment orders (block IP, kill PID, ...) to a Wazuh agent. By
default it runs in **dry-run** mode: the intended command is logged but never
executed, which is the safe choice while validating the pipeline. When
``dry_run`` is disabled it drives the Wazuh Manager REST API
(``PUT /active-response``) to dispatch the command to the target agent.

Two safety controls gate every dispatch, so even with ``dry_run`` disabled the
blast radius stays bounded:

* **Allowlist** — only command names explicitly listed in ``command_allowlist``
  may ever be dispatched. Anything else (including any free-form text from the
  LLM) is refused. The LLM's suggested command is advisory only and is never
  executed verbatim.
* **Kill-switch** — if ``kill_switch_file`` exists on disk, every dispatch is
  suppressed regardless of mode. ``touch``-ing that file is an instant global
  off-switch for automated response.
* **Idempotency** — an optional TTL window collapses repeats of the same
  (agent, command, arguments) order so a burst of identical alerts cannot fire
  the same containment over and over.
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Iterable, List, Optional

import requests

from .verdict_cache import TTLCache

logger = logging.getLogger(__name__)


class WazuhResponder:
    """Triggers Wazuh Active Response, with dry-run, an allowlist and a kill-switch."""

    def __init__(
        self,
        *,
        dry_run: bool = True,
        command_allowlist: Optional[Iterable[str]] = None,
        kill_switch_file: Optional[str] = None,
        default_command: str = "firewall-drop",
        wazuh_api_url: Optional[str] = None,
        wazuh_api_user: Optional[str] = None,
        wazuh_api_password: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 30,
        dedup_ttl_seconds: float = 0.0,
        time_fn: Optional[Callable[[], float]] = None,
    ) -> None:
        self.dry_run = dry_run
        # Empty allowlist => deny every dispatch (safe default).
        self.command_allowlist = set(command_allowlist or [])
        self.kill_switch_file = kill_switch_file or None
        self.default_command = default_command
        self.wazuh_api_url = wazuh_api_url.rstrip("/") if wazuh_api_url else None
        self.wazuh_api_user = wazuh_api_user
        self.wazuh_api_password = wazuh_api_password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        # Cached JWT bearer token for the Wazuh API (lazily obtained).
        self._token: Optional[str] = None
        # Idempotency window: remembers recently dispatched orders so duplicates
        # within ``dedup_ttl_seconds`` are skipped. Disabled when the TTL is 0.
        self.dedup_ttl_seconds = float(dedup_ttl_seconds)
        self._recent: Optional[TTLCache] = None
        if self.dedup_ttl_seconds > 0:
            cache_kwargs: dict = {"max_entries": 4096, "ttl_seconds": self.dedup_ttl_seconds}
            if time_fn is not None:
                cache_kwargs["time_fn"] = time_fn
            self._recent = TTLCache(**cache_kwargs)

    def _kill_switch_engaged(self) -> bool:
        """Return True if the kill-switch file is present (forces a no-op)."""
        return bool(self.kill_switch_file) and os.path.exists(self.kill_switch_file)

    @staticmethod
    def _dedup_key(agent_id: str, command: str, arguments: List[str]) -> str:
        """Stable key identifying one containment order for the dedup window."""
        return "\x1f".join([str(agent_id), str(command), *map(str, arguments)])

    def _remember(self, key: str) -> None:
        """Record a dispatched order so an immediate repeat is deduplicated."""
        if self._recent is not None:
            self._recent.put(key, True)

    def trigger_active_response(self, agent_id: str, command: str, arguments: List[str]) -> bool:
        """Dispatch an active-response ``command`` to ``agent_id``.

        Args:
            agent_id: Target Wazuh agent id (e.g. ``"001"``).
            command: Active-response command **name** configured on the manager
                (e.g. ``"firewall-drop"``). Must be present in the allowlist.
            arguments: Extra arguments forwarded to the command.

        Returns:
            True only if the order was actually dispatched (or logged in
            dry-run). False if it was refused (kill-switch, not allowlisted,
            misconfiguration) or the API call failed.
        """
        printable = f"agent={agent_id} command={command!r} args={arguments}"

        # Global kill-switch: presence of the file suppresses everything, even
        # in real mode. Checked first so nothing can slip past it.
        if self._kill_switch_engaged():
            logger.warning(
                "[KILL-SWITCH active: %s] Active Response suppressed -> %s",
                self.kill_switch_file, printable,
            )
            return False

        # Allowlist: only explicitly permitted command names may be dispatched.
        if command not in self.command_allowlist:
            logger.error(
                "Active Response command %r not in allowlist %s; refusing -> %s",
                command, sorted(self.command_allowlist), printable,
            )
            return False

        # Idempotency: collapse a repeat of the same order within the TTL window.
        # Treated as already handled (True) so the caller does not retry.
        key = self._dedup_key(agent_id, command, arguments)
        if self._recent is not None and self._recent.get(key) is not None:
            logger.info(
                "Active Response deduplicated (within %.0fs window) -> %s",
                self.dedup_ttl_seconds, printable,
            )
            return True

        if self.dry_run:
            logger.warning("[DRY-RUN] Active Response NOT executed (allowed) -> %s", printable)
            self._remember(key)
            return True

        if not self.wazuh_api_url:
            logger.error("Active Response requested but no wazuh_api_url configured: %s", printable)
            return False

        try:
            dispatched = self._dispatch_via_api(agent_id, command, arguments)
        except requests.RequestException as exc:
            logger.error("Active Response API call failed (%s): %s", printable, exc)
            return False
        if dispatched:
            self._remember(key)
        return dispatched

    # ------------------------------------------------------------------ #
    # Wazuh Manager REST API integration (only used when dry_run is False)
    # ------------------------------------------------------------------ #
    def _authenticate(self) -> str:
        """Obtain and cache a JWT bearer token from the Wazuh API."""
        if self._token:
            return self._token
        response = requests.post(
            f"{self.wazuh_api_url}/security/user/authenticate",
            auth=(self.wazuh_api_user or "", self.wazuh_api_password or ""),
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()
        self._token = response.json()["data"]["token"]
        return self._token

    def _dispatch_via_api(self, agent_id: str, command: str, arguments: List[str]) -> bool:
        """Send the active-response command through ``PUT /active-response``."""
        token = self._authenticate()
        # The Wazuh API expects the command prefixed with '!' and a custom
        # argument list inside the request body.
        body = {"command": f"!{command}", "arguments": arguments}
        response = requests.put(
            f"{self.wazuh_api_url}/active-response",
            params={"agents_list": agent_id},
            json=body,
            headers={"Authorization": f"Bearer {token}"},
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()
        logger.info("Active Response dispatched to agent %s: %s", agent_id, command)
        return True
