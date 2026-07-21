from __future__ import annotations

from wazuh_viewer.models import Alert, AlertTriage, FilterState, SeverityBand, TriageStatus
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
    options = [("all", "Wszystkie statusy")]
    for status in TriageStatus:
        options.append((status.value, status.label))
    return options


def triage_action_options() -> list[tuple[str, str]]:
    return [(status.value, status.label) for status in TriageStatus]
