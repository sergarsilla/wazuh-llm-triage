"""Tests for the verdict cache: signature stability and TTL/LRU behaviour."""

from __future__ import annotations

from src.verdict_cache import TTLCache, alert_signature


def _anomaly_alert(
    *,
    command: str = "docker ps -a",
    process: str = "docker",
    user: str = "ubuntu",
    agent_name: str = "app-host-02",
    rule_id: str = "100100",
) -> dict:
    return {
        "rule": {"id": rule_id, "level": 12, "groups": ["anomaly_detector"]},
        "agent": {"id": "000", "name": "wazuh-manager"},
        "data": {
            "anomaly_detector": {
                "agent_id": "002",
                "agent_name": agent_name,
                "process_name": process,
                "user": user,
                "command": command,
            }
        },
    }


class TestAlertSignature:
    def test_identical_alerts_share_signature(self):
        assert alert_signature(_anomaly_alert()) == alert_signature(_anomaly_alert())

    def test_whitespace_only_differences_collapse(self):
        a = alert_signature(_anomaly_alert(command="docker ps -a"))
        b = alert_signature(_anomaly_alert(command="docker   ps   -a "))
        assert a == b

    def test_different_command_differs(self):
        a = alert_signature(_anomaly_alert(command="docker ps -a"))
        b = alert_signature(_anomaly_alert(command="docker rm -f web"))
        assert a != b

    def test_different_host_differs(self):
        a = alert_signature(_anomaly_alert(agent_name="app-host-02"))
        b = alert_signature(_anomaly_alert(agent_name="app-host-03"))
        assert a != b

    def test_different_user_differs(self):
        a = alert_signature(_anomaly_alert(user="ubuntu"))
        b = alert_signature(_anomaly_alert(user="root"))
        assert a != b

    def test_non_anomaly_alert_is_uncacheable(self):
        plain = {
            "rule": {"id": "5715", "level": 7},
            "agent": {"id": "003", "name": "jump-01"},
            "data": {"srcip": "10.20.0.50", "dstuser": "alice"},
        }
        assert alert_signature(plain) is None

    def test_anomaly_without_command_or_process_is_uncacheable(self):
        assert alert_signature(_anomaly_alert(command="", process="")) is None

    def test_process_only_anomaly_is_cacheable(self):
        assert alert_signature(_anomaly_alert(command="", process="docker")) is not None

    def test_long_command_truncated_to_a_stable_prefix(self):
        # Both commands share the first 256 normalized chars; the differing tail
        # is past the cap, so the truncation makes them collapse to one key.
        base = "a " * 500
        s1 = alert_signature(_anomaly_alert(command=base + "X"))
        s2 = alert_signature(_anomaly_alert(command=base + "Y"))
        assert s1 == s2


class _Clock:
    """Deterministic injectable clock for TTL tests."""

    def __init__(self, start: float = 0.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class TestTTLCache:
    def test_get_miss_on_absent_key(self):
        assert TTLCache().get("nope") is None

    def test_put_then_get_hit(self):
        cache = TTLCache()
        cache.put("k", {"v": 1})
        assert cache.get("k") == {"v": 1}

    def test_entry_expires_after_ttl(self):
        clock = _Clock()
        cache = TTLCache(ttl_seconds=10, time_fn=clock)
        cache.put("k", "v")
        clock.advance(9)
        assert cache.get("k") == "v"
        clock.advance(2)  # now 11 > 10 -> expired
        assert cache.get("k") is None

    def test_lru_eviction_at_capacity(self):
        cache = TTLCache(max_entries=2)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.get("a")  # 'a' becomes most-recently-used
        cache.put("c", 3)  # evicts the LRU entry -> 'b'
        assert cache.get("a") == 1
        assert cache.get("c") == 3
        assert cache.get("b") is None

    def test_size_never_exceeds_max(self):
        cache = TTLCache(max_entries=3)
        for i in range(10):
            cache.put(f"k{i}", i)
        assert len(cache) == 3

    def test_expired_entries_purged_on_put(self):
        clock = _Clock()
        cache = TTLCache(max_entries=100, ttl_seconds=5, time_fn=clock)
        cache.put("old", 1)
        clock.advance(6)
        cache.put("new", 2)  # purges the expired 'old' entry
        assert len(cache) == 1
        assert cache.get("old") is None
        assert cache.get("new") == 2
