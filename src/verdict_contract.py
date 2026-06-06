"""Shared identifiers for the verdict alerts this middleware re-injects into Wazuh.

After triaging an alert, the pipeline writes its verdict back into Wazuh as a
normal alert (see ``wazuh_injector``) so it appears in the dashboard and can
drive escalation/notification rules. Those re-injected verdicts must be
recognised consistently in three places that would otherwise drift apart:

* the injector that writes them (``src/wazuh_injector.py``),
* the manager-side rules that score them (``rules/llm_triage_rules.xml``),
* the ingester that must NOT re-triage them (``src/ingester.py``), since a
  verdict re-enters ``alerts.json`` at a high ``rule.level`` and would otherwise
  be triaged again in an endless loop.

Single-sourcing the contract here keeps those three in sync.
"""

from __future__ import annotations

# Wazuh "location" tag and decoded-JSON key used for re-injected verdicts. The
# decoded payload lands under ``data.<VERDICT_LOCATION>`` in the alert.
VERDICT_LOCATION = "llm_triage"

# Manager-side rule ids that fire on a re-injected verdict (see the rules XML).
VERDICT_RULE_IDS = frozenset({"100110", "100111"})
