from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from wazuh_viewer.models import AlertTriage, TriageStatus


class TriageStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, dict] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self._data = {}
            return
        text = self.path.read_text(encoding="utf-8").strip()
        self._data = json.loads(text) if text else {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get(self, alert_id: str) -> AlertTriage:
        row = self._data.get(alert_id)
        if not row:
            return AlertTriage(alert_id=alert_id)
        return AlertTriage(
            alert_id=alert_id,
            status=TriageStatus(row.get("status", TriageStatus.NEW)),
            analyst=str(row.get("analyst", "")),
            notes=str(row.get("notes", "")),
            updated_at=str(row.get("updated_at", "")),
        )

    def upsert(
        self,
        alert_id: str,
        *,
        status: TriageStatus | None = None,
        analyst: str | None = None,
        notes: str | None = None,
    ) -> AlertTriage:
        current = self.get(alert_id)
        if status is not None:
            current.status = status
        if analyst is not None:
            current.analyst = analyst
        if notes is not None:
            current.notes = notes
        current.updated_at = datetime.now(timezone.utc).isoformat()
        self._data[alert_id] = {
            "status": current.status.value,
            "analyst": current.analyst,
            "notes": current.notes,
            "updated_at": current.updated_at,
        }
        self.save()
        return current
