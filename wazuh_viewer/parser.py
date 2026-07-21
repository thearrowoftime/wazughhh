from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from wazuh_viewer.models import Alert


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [str(value)]


def parse_alert(payload: dict[str, Any]) -> Alert | None:
    rule = payload.get("rule") or {}
    agent = payload.get("agent") or {}
    mitre = rule.get("mitre") or {}

    rule_id = str(rule.get("id", ""))
    if not rule_id and not rule.get("description"):
        return None

    return Alert(
        alert_id=Alert.compute_id(payload),
        timestamp=str(payload.get("timestamp", "")),
        rule_id=rule_id,
        rule_level=int(rule.get("level", 0)),
        description=str(rule.get("description", "Brak opisu")),
        host=str(agent.get("name") or agent.get("id") or "unknown"),
        agent_id=str(agent.get("id", "")),
        mitre_ids=_as_list(mitre.get("id")),
        mitre_tactics=_as_list(mitre.get("tactic")),
        mitre_techniques=_as_list(mitre.get("technique")),
        raw=payload,
    )


def load_alerts_from_file(path: Path) -> list[Alert]:
    text = path.read_text(encoding="utf-8")
    alerts: list[Alert] = []

    if path.suffix.lower() == ".jsonl":
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            alert = parse_alert(payload)
            if alert:
                alerts.append(alert)
        return alerts

    data = json.loads(text)
    if isinstance(data, dict):
        hits = (
            data.get("hits", {}).get("hits")
            or data.get("data", {}).get("affected_items")
            or data.get("data", {}).get("items")
            or []
        )
        for item in hits:
            source = item.get("_source", item)
            alert = parse_alert(source)
            if alert:
                alerts.append(alert)
        return alerts

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            alert = parse_alert(item)
            if alert:
                alerts.append(alert)
        return alerts

    raise ValueError(f"Nieobsługiwany format pliku: {path}")


def load_alerts_from_iterable(items: Iterable[dict[str, Any]]) -> list[Alert]:
    alerts: list[Alert] = []
    for item in items:
        alert = parse_alert(item)
        if alert:
            alerts.append(alert)
    return alerts
