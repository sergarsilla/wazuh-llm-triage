"""Re-inject triage verdicts into Wazuh via the manager's queue socket.

After the LLM triages an alert, the verdict is written back into Wazuh as a
normal alert so it shows up in the dashboard and can drive escalation /
notification rules (see ``rules/llm_triage_rules.xml``). Wazuh's queue protocol
expects datagrams of the form ``<queue>:<location>:<json>``; we use queue id
``1`` and the ``llm_triage`` location, so the decoded payload lands under
``data.llm_triage`` in the resulting alert.

This realises the two-level design: the raw anomaly stays a low "review" signal
and the escalation to a high, e-mailing level happens only when the LLM verdict
is ``MALICIOUS``. Socket failures (manager down, wrong path, permissions) are
caught and reported as ``False`` so a transient problem never crashes the
triage pipeline.
"""

from __future__ import annotations

import json
import logging
import socket
from typing import Optional

from .verdict_contract import VERDICT_LOCATION

logger = logging.getLogger(__name__)

# Wazuh queue-message prefix: queue id "1" and our verdict location tag.
_QUEUE_PREFIX = f"1:{VERDICT_LOCATION}:"

# Cap on the embedded justification so a verdict cannot exceed Wazuh's
# queue-message size limit.
_MAX_JUSTIFICATION_LEN = 1024


class WazuhVerdictInjector:
    """Send LLM triage verdicts to the Wazuh manager via its UNIX datagram socket."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path

    def send_verdict(
        self,
        *,
        verdict: str,
        risk_level: str,
        requires_response: bool,
        agent_id: str,
        rule_id: str,
        justification: str = "",
        correlation_id: str = "",
    ) -> bool:
        """Inject a single verdict alert. Returns True on success, False on error.

        Args:
            verdict: ``"MALICIOUS"`` or ``"FALSE_POSITIVE"`` (drives the rule).
            risk_level: LLM risk level (LOW/MEDIUM/HIGH/CRITICAL), for context.
            requires_response: Whether the LLM deemed active response warranted.
            agent_id: The affected Wazuh agent id.
            rule_id: The id of the original alert that was triaged.
            justification: The LLM's technical justification (truncated).
            correlation_id: The id of the original alert, for cross-reference.
        """
        payload = {
            VERDICT_LOCATION: {
                "verdict": verdict,
                "risk_level": risk_level,
                "requires_response": bool(requires_response),
                "agent_id": agent_id,
                "rule_id": rule_id,
                "justification": justification[:_MAX_JUSTIFICATION_LEN],
                "correlation_id": correlation_id,
            }
        }
        message = f"{_QUEUE_PREFIX}{json.dumps(payload, ensure_ascii=False)}"

        client: Optional[socket.socket] = None
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            client.sendto(message.encode("utf-8"), self.socket_path)
            return True
        except OSError as exc:
            logger.error("Verdict injection failed (socket %s): %s", self.socket_path, exc)
            return False
        finally:
            if client is not None:
                client.close()
