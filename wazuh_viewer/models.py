from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class TriageStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

    @classmethod
    def labels(cls) -> dict[str, str]:
        return {
            cls.NEW: "New",
            cls.INVESTIGATING: "Investigating",
            cls.ESCALATED: "Escalated",
            cls.RESOLVED: "Resolved",
            cls.FALSE_POSITIVE: "False Positive",
        }

    @property
    def label(self) -> str:
        return self.labels()[self.value]


class SeverityBand(StrEnum):
    ALL = "all"
    LOW = "low"          # 0-6
    MEDIUM = "medium"    # 7-11
    HIGH = "high"        # 12-14
    CRITICAL = "critical"  # 15+

    @classmethod
    def labels(cls) -> dict[str, str]:
        return {
            cls.ALL: "All",
            cls.LOW: "Low (0-6)",
            cls.MEDIUM: "Medium (7-11)",
            cls.HIGH: "High (12-14)",
            cls.CRITICAL: "Critical (15+)",
        }

    @property
    def label(self) -> str:
        return self.labels()[self.value]

    def matches(self, level: int) -> bool:
        if self == SeverityBand.ALL:
            return True
        if self == SeverityBand.LOW:
            return level <= 6
        if self == SeverityBand.MEDIUM:
            return 7 <= level <= 11
        if self == SeverityBand.HIGH:
            return 12 <= level <= 14
        return level >= 15


@dataclass
class Alert:
    alert_id: str
    timestamp: str
    rule_id: str
    rule_level: int
    description: str
    host: str
    agent_id: str
    mitre_ids: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_label(self) -> str:
        if self.rule_level >= 15:
            return "CRITICAL"
        if self.rule_level >= 12:
            return "HIGH"
        if self.rule_level >= 7:
            return "MEDIUM"
        return "LOW"

    @property
    def mitre_display(self) -> str:
        if not self.mitre_ids:
            return "—"
        return ", ".join(self.mitre_ids)

    @staticmethod
    def compute_id(payload: dict[str, Any]) -> str:
        rule = payload.get("rule") or {}
        agent = payload.get("agent") or {}
        key = "|".join(
            [
                str(payload.get("timestamp", "")),
                str(rule.get("id", "")),
                str(agent.get("id", "")),
                str(payload.get("id", "")),
            ]
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class AlertTriage:
    alert_id: str
    status: TriageStatus = TriageStatus.NEW
    analyst: str = ""
    notes: str = ""
    updated_at: str = ""


@dataclass
class FilterState:
    severity: SeverityBand = SeverityBand.ALL
    host: str = ""
    mitre_tag: str = ""
    triage_status: str = "all"
    search: str = ""

    def is_active(self) -> bool:
        return any(
            [
                self.severity != SeverityBand.ALL,
                bool(self.host.strip()),
                bool(self.mitre_tag.strip()),
                self.triage_status != "all",
                bool(self.search.strip()),
            ]
        )


def severity_color(level: int) -> str:
    if level >= 15:
        return "red"
    if level >= 12:
        return "orange1"
    if level >= 7:
        return "yellow"
    return "green"


def triage_color(status: TriageStatus) -> str:
    return {
        TriageStatus.NEW: "cyan",
        TriageStatus.INVESTIGATING: "yellow",
        TriageStatus.ESCALATED: "red",
        TriageStatus.RESOLVED: "green",
        TriageStatus.FALSE_POSITIVE: "dim",
    }.get(status, "white")
