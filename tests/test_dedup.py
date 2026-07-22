"""Tests for alert deduplication / grouping."""
import pytest
from wazuh_viewer.models import Alert, AlertGroup
from wazuh_viewer.filters import group_alerts


def _make_alert(rule_id: str, host: str, ts: str, level: int = 5) -> Alert:
    from wazuh_viewer.models import Alert
    import hashlib
    aid = hashlib.sha256(f"{ts}{rule_id}{host}".encode()).hexdigest()[:16]
    return Alert(
        alert_id=aid,
        timestamp=ts,
        rule_id=rule_id,
        rule_level=level,
        description=f"Rule {rule_id} on {host}",
        host=host,
        agent_id="001",
    )


class TestGroupAlerts:
    def test_same_rule_host_grouped(self):
        alerts = [
            _make_alert("5710", "web-01", "2026-07-10T06:00:00Z"),
            _make_alert("5710", "web-01", "2026-07-10T06:05:00Z"),
            _make_alert("5710", "web-01", "2026-07-10T06:10:00Z"),
        ]
        groups = group_alerts(alerts, window_minutes=60)
        assert len(groups) == 1
        assert groups[0].count == 3
        assert groups[0].rule_id == "5710"
        assert groups[0].host == "web-01"

    def test_different_hosts_separate_groups(self):
        alerts = [
            _make_alert("5710", "web-01", "2026-07-10T06:00:00Z"),
            _make_alert("5710", "web-02", "2026-07-10T06:01:00Z"),
        ]
        groups = group_alerts(alerts, window_minutes=60)
        assert len(groups) == 2

    def test_different_rules_separate_groups(self):
        alerts = [
            _make_alert("5710", "web-01", "2026-07-10T06:00:00Z"),
            _make_alert("5712", "web-01", "2026-07-10T06:01:00Z"),
        ]
        groups = group_alerts(alerts, window_minutes=60)
        assert len(groups) == 2

    def test_time_gap_splits_groups(self):
        alerts = [
            _make_alert("5710", "web-01", "2026-07-10T06:00:00Z"),
            _make_alert("5710", "web-01", "2026-07-10T08:30:00Z"),  # 2.5h later
        ]
        groups = group_alerts(alerts, window_minutes=60)
        assert len(groups) == 2

    def test_within_window_stays_same_group(self):
        alerts = [
            _make_alert("5710", "web-01", "2026-07-10T06:00:00Z"),
            _make_alert("5710", "web-01", "2026-07-10T06:45:00Z"),  # 45 min later
        ]
        groups = group_alerts(alerts, window_minutes=60)
        assert len(groups) == 1
        assert groups[0].count == 2

    def test_first_last_seen_correct(self):
        alerts = [
            _make_alert("5710", "web-01", "2026-07-10T06:00:00Z"),
            _make_alert("5710", "web-01", "2026-07-10T06:10:00Z"),
            _make_alert("5710", "web-01", "2026-07-10T06:20:00Z"),
        ]
        groups = group_alerts(alerts, window_minutes=60)
        g = groups[0]
        assert "06:00:00" in g.first_seen
        assert "06:20:00" in g.last_seen

    def test_max_severity_within_group(self):
        alerts = [
            _make_alert("5710", "web-01", "2026-07-10T06:00:00Z", level=5),
            _make_alert("5710", "web-01", "2026-07-10T06:05:00Z", level=12),
            _make_alert("5710", "web-01", "2026-07-10T06:10:00Z", level=7),
        ]
        groups = group_alerts(alerts, window_minutes=60)
        assert groups[0].rule_level == 12

    def test_empty_alerts(self):
        groups = group_alerts([], window_minutes=60)
        assert groups == []

    def test_representative_id(self):
        alerts = [
            _make_alert("5710", "web-01", "2026-07-10T06:00:00Z"),
            _make_alert("5710", "web-01", "2026-07-10T06:05:00Z"),
        ]
        groups = group_alerts(alerts, window_minutes=60)
        assert groups[0].representative_id != ""
