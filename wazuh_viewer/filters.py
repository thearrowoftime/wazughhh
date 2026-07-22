from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from wazuh_viewer.models import Alert, AlertGroup, AlertTriage, FilterState, SeverityBand, TriageStatus
from wazuh_viewer.storage import TriageStore


def apply_filters(
    alerts: list[Alert],
    filters: FilterState,
    triage_store: TriageStore,
) -> list[Alert]:
    result: list[Alert] = []
    host_q = filters.host.strip().lower()
    mitre_q = filters.mitre_tag.strip().lower()
    search_q = filters.search.strip().lower()

    for alert in alerts:
        triage = triage_store.get(alert.alert_id)

        if not filters.severity.matches(alert.rule_level):
            continue

        if host_q and host_q not in alert.host.lower():
            continue

        if mitre_q:
            haystack = " ".join(
                alert.mitre_ids + alert.mitre_tactics + alert.mitre_techniques
            ).lower()
            if mitre_q not in haystack:
                continue

        if filters.triage_status != "all":
            if triage.status.value != filters.triage_status:
                continue

        if search_q:
            blob = " ".join(
                [
                    alert.description,
                    alert.rule_id,
                    alert.host,
                    alert.mitre_display,
                    triage.notes,
                    triage.analyst,
                ]
            ).lower()
            if search_q not in blob:
                continue

        result.append(alert)

    return result


def unique_hosts(alerts: list[Alert]) -> list[str]:
    return sorted({a.host for a in alerts})


def unique_mitre_tags(alerts: list[Alert]) -> list[str]:
    tags: set[str] = set()
    for alert in alerts:
        tags.update(alert.mitre_ids)
        tags.update(alert.mitre_tactics)
        tags.update(alert.mitre_techniques)
    return sorted(tags)


def severity_options() -> list[tuple[str, str]]:
    return [(band.value, band.label) for band in SeverityBand]


def triage_filter_options() -> list[tuple[str, str]]:
    options = [("all", "All statuses")]
    for status in TriageStatus:
        options.append((status.value, status.label))
    return options


def triage_action_options() -> list[tuple[str, str]]:
    return [(status.value, status.label) for status in TriageStatus]


# ---------------------------------------------------------------------------
# Alert deduplication
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime | None:
    """Parse ISO-8601 or syslog-like timestamp to datetime (UTC-aware)."""
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def group_alerts(
    alerts: list[Alert],
    window_minutes: int = 60,
) -> list[AlertGroup]:
    """
    Group alerts by (rule_id, host).  Alerts are split into separate groups
    if the gap between consecutive events exceeds *window_minutes*.

    Returns groups sorted by last_seen descending (most recent first).
    """
    # Sort by host+rule+time first
    def sort_key(a: Alert) -> tuple[str, str, str]:
        return (a.host, a.rule_id, a.timestamp)

    sorted_alerts = sorted(alerts, key=sort_key)
    window = timedelta(minutes=window_minutes)

    # bucket_key → (open_group, last_dt)
    open_groups: dict[str, tuple[AlertGroup, datetime | None]] = {}
    finished: list[AlertGroup] = []
    group_idx = 0

    for alert in sorted_alerts:
        bk = f"{alert.rule_id}|{alert.host}"
        alert_dt = _parse_ts(alert.timestamp)

        if bk in open_groups:
            grp, last_dt = open_groups[bk]
            # Close and reopen if gap > window
            if last_dt and alert_dt and (alert_dt - last_dt) > window:
                finished.append(grp)
                del open_groups[bk]

        if bk not in open_groups:
            grp = AlertGroup(
                group_key=f"{bk}#{group_idx}",
                rule_id=alert.rule_id,
                host=alert.host,
                rule_level=alert.rule_level,
                description=alert.description,
                mitre_ids=list(dict.fromkeys(alert.mitre_ids)),
                mitre_tactics=list(dict.fromkeys(alert.mitre_tactics)),
                count=0,
                first_seen=alert.timestamp,
                last_seen=alert.timestamp,
                alerts=[],
            )
            open_groups[bk] = (grp, alert_dt)
            group_idx += 1

        grp, _ = open_groups[bk]
        grp.alerts.append(alert)
        grp.count += 1
        grp.last_seen = alert.timestamp
        # Keep highest severity within group
        if alert.rule_level > grp.rule_level:
            grp.rule_level = alert.rule_level
        # Merge MITRE IDs
        for mid in alert.mitre_ids:
            if mid not in grp.mitre_ids:
                grp.mitre_ids.append(mid)
        open_groups[bk] = (grp, alert_dt)

    for grp, _ in open_groups.values():
        finished.append(grp)

    # Sort most-recent first
    finished.sort(key=lambda g: g.last_seen, reverse=True)
    return finished
