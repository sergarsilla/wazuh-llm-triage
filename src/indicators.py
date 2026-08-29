"""Deterministic command indicators used to gate verdict escalation.

The LLM decides whether an alert is malicious; these patterns decide whether that
verdict may reach the e-mail tier. A match is necessary, never sufficient, so the
gate can only withhold an escalation, never raise one.

Patterns describe acts, not vocabulary: searching a filesystem for the string
``base64_decode`` matches nothing, decoding a payload into a shell matches.
"""

from __future__ import annotations

import re
from typing import Dict, FrozenSet, List, Sequence

_INTERPRETERS = r"(?:ba|z|k|da)?sh|python[0-9.]*|perl|ruby|node|php"
_SECURITY_SERVICES = r"wazuh[\w-]*|suricata|fail2ban|auditd|falco|clamav|apparmor|selinux"
_SYSTEM_PATHS = r"etc|usr|bin|sbin|opt|srv|var/www"

# Mirrors the anomaly detector's feature flags. Duplicated rather than shared
# because the two services version independently and the gate must hold against
# any detector release, including one whose alerts carry no indicators.
INDICATOR_PATTERNS: Dict[str, re.Pattern[str]] = {
    "pipe_to_interpreter": re.compile(
        rf"\|\s*(?:sudo\s+)?(?:/\S*/)?(?:{_INTERPRETERS})\b", re.IGNORECASE
    ),
    # Loopback targets are local API reads (e.g. a monitoring container querying
    # its own endpoint), not downloads from a remote host, so they are excluded.
    "remote_fetch": re.compile(
        r"\b(?:curl|wget|fetch)\b.*?\b(?:https?|ftp)://"
        r"(?!localhost\b|127\.|0\.0\.0\.0|\[?::1\]?)",
        re.IGNORECASE,
    ),
    "raw_socket_redirect": re.compile(r"/dev/(?:tcp|udp)/", re.IGNORECASE),
    "encoded_payload": re.compile(
        r"\bbase64\s+(?:-d|--decode)\b|\bxxd\s+-r\b|\bopenssl\s+enc\s+-d\b|"
        r"\bbase64\.b64decode\b",
        re.IGNORECASE,
    ),
    "interactive_shell_spawn": re.compile(
        rf"\b(?:{_INTERPRETERS})\s+-i\b|\bnc\b[^|]*\s-\w*e\w*\s|\bsocat\b.*\bexec\b|"
        r"\bpty\.spawn\b",
        re.IGNORECASE,
    ),
    "security_tooling_disabled": re.compile(
        rf"\b(?:systemctl|service)\s+(?:stop|disable|mask)\b.*(?:{_SECURITY_SERVICES})|"
        rf"\b(?:pkill|killall)\b.*(?:{_SECURITY_SERVICES})",
        re.IGNORECASE,
    ),
    "log_tampering": re.compile(
        r"\b(?:rm|shred|truncate)\b[^|]*(?:/var/log|\.log)\b|"
        r"\bjournalctl\s+--(?:vacuum|rotate)|>\s*/var/log/",
        re.IGNORECASE,
    ),
    "credential_access": re.compile(
        r"/etc/(?:shadow|gshadow)\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.ssh/id_|"
        r"\.pgpass\b|\.aws/credentials\b|\.docker/config\.json\b",
        re.IGNORECASE,
    ),
    "persistence_config": re.compile(
        r"\bcrontab\b|/etc/cron|\bsystemctl\s+enable\b|/etc/systemd/system|"
        r"/etc/rc\.local\b|\.bash(?:rc|_profile)\b",
        re.IGNORECASE,
    ),
    "privileged_account_config": re.compile(
        r"\b(?:useradd|adduser|userdel)\b|\busermod\b[^|]*-a?G\b|"
        r"\bauthorized_keys\b|/etc/sudoers|\bvisudo\b",
        re.IGNORECASE,
    ),
    "container_escape": re.compile(
        r"\bdocker\s+run\b[^|]*(?:--privileged\b|--pid[= ]host\b|--net(?:work)?[= ]host\b|"
        r"(?:-v|--volume)\s*/:)|\bnsenter\b",
        re.IGNORECASE,
    ),
    "package_management": re.compile(
        r"\b(?:apt|apt-get|yum|dnf|pacman|apk|zypper|snap)\b\s+"
        r"(?:install|remove|purge|upgrade|update|-S)\b",
        re.IGNORECASE,
    ),
    # File mutation; read-only traversal such as `find … -exec md5sum` must not match.
    "destructive_file_write": re.compile(
        r"\bfind\b[^|;]*\s-delete\b|"
        r"\bfind\b[^|;]*-exec\s+(?:/\S*/)?"
        r"(?:rm|mv|cp|dd|sed|tee|chmod|chown|truncate|shred)\b|"
        r"\bsed\b\s+(?:[^|;]*\s)?-i(?:\.\S+)?\b|"
        rf"\btee\b\s+(?:-a\s+)?/(?:{_SYSTEM_PATHS})/|"
        r"\bchmod\b[^|;]*\s\+x\b",
        re.IGNORECASE,
    ),
}

# Indicators that escalate even when the LLM dismisses them: blinding the
# monitoring or reading credentials must not depend on the model agreeing.
DEFAULT_CRITICAL_INDICATORS: FrozenSet[str] = frozenset(
    {"security_tooling_disabled", "log_tampering", "credential_access"}
)


def match_indicators(command: str) -> List[str]:
    """Return the indicators the command matches; empty means shape-only anomaly."""
    if not command:
        return []
    return [name for name, pattern in INDICATOR_PATTERNS.items() if pattern.search(command)]


def parse_critical_indicators(value: object) -> FrozenSet[str]:
    """Parse a comma-separated string or sequence; unknown names are dropped.

    Dropping rather than honouring a typo keeps a misconfiguration from silently
    widening the set of indicators that escalate on their own.
    """
    if value is None:
        return DEFAULT_CRITICAL_INDICATORS
    items: Sequence[str] = (
        value if isinstance(value, (list, tuple)) else str(value).split(",")
    )
    names = {str(item).strip() for item in items if str(item).strip()}
    return frozenset(names & set(INDICATOR_PATTERNS))
