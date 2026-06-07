"""Identifiers for the verdict alerts this middleware re-injects into Wazuh.

Single-sourced here so the injector (``wazuh_injector``), the manager-side rules
(``rules/llm_triage_rules.xml``) and the ingester's self-skip stay in sync. The
ingester must never re-triage a verdict: it re-enters ``alerts.json`` at a high
``rule.level`` and would otherwise loop forever.
"""

from __future__ import annotations

# Wazuh "location" tag and decoded-JSON key used for re-injected verdicts. The
# decoded payload lands under ``data.<VERDICT_LOCATION>`` in the alert.
VERDICT_LOCATION = "llm_triage"

# Manager-side rule ids that fire on a re-injected verdict (see the rules XML).
VERDICT_RULE_IDS = frozenset({"100110", "100111"})
