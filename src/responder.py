"""Wazuh Active Response module.

Issues containment orders (block IP, kill PID, ...) to a Wazuh agent. By
default it runs in **dry-run** mode: the intended command is logged but never
executed, which is the safe choice while validating the pipeline. When
``dry_run`` is disabled it drives the Wazuh Manager REST API
(``PUT /active-response``) to dispatch the command to the target agent.
"""

from __future__ import annotations

import logging
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)


class WazuhResponder:
    """Triggers Wazuh Active Response, with a non-destructive dry-run mode."""

    def __init__(
        self,
        *,
        dry_run: bool = True,
        wazuh_api_url: Optional[str] = None,
        wazuh_api_user: Optional[str] = None,
        wazuh_api_password: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.dry_run = dry_run
        self.wazuh_api_url = wazuh_api_url.rstrip("/") if wazuh_api_url else None
        self.wazuh_api_user = wazuh_api_user
        self.wazuh_api_password = wazuh_api_password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        # Cached JWT bearer token for the Wazuh API (lazily obtained).
        self._token: Optional[str] = None

    def trigger_active_response(self, agent_id: str, command: str, arguments: List[str]) -> bool:
        """Dispatch an active-response ``command`` to ``agent_id``.

        Args:
            agent_id: Target Wazuh agent id (e.g. ``"001"``).
            command: Active-response command name configured on the manager
                (e.g. ``"firewall-drop"``), or a free-form suggested command in
                dry-run mode.
            arguments: Extra arguments forwarded to the command.

        Returns:
            True if the order was dispatched (or logged in dry-run) successfully,
            False on failure.
        """
        printable = f"agent={agent_id} command={command!r} args={arguments}"

        if self.dry_run:
            logger.warning("[DRY-RUN] Active Response NOT executed -> %s", printable)
            return True

        if not self.wazuh_api_url:
            logger.error("Active Response requested but no wazuh_api_url configured: %s", printable)
            return False

        try:
            return self._dispatch_via_api(agent_id, command, arguments)
        except requests.RequestException as exc:
            logger.error("Active Response API call failed (%s): %s", printable, exc)
            return False

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
