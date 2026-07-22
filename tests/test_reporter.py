"""Tests for shift report generation."""
import tempfile
from pathlib import Path

from wazuh_viewer.models import Alert, TriageStatus
from wazuh_viewer.storage import TriageStore
from wazuh_viewer.reporter import generate_markdown_report, generate_csv_report, save_report


def _make_alert(rule_id: str, host: str, level: int = 5) -> Alert:
    import hashlib
    ts = "2026-07-10T06:00:00Z"
    aid = hashlib.sha256(f"{ts}{rule_id}{host}".encode()).hexdigest()[:16]
    return Alert(
        alert_id=aid,
        timestamp=ts,
        rule_id=rule_id,
        rule_level=level,
        description=f"Rule {rule_id} triggered on {host}",
        host=host,
        agent_id="001",
        mitre_ids=["T1110"],
    )


def _tmp_store() -> tuple[TriageStore, Path]:
    tf = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tf.close()
    store = TriageStore(Path(tf.name))
    return store, Path(tf.name)


class TestMarkdownReport:
    def test_contains_header(self):
        alerts = [_make_alert("5710", "web-01")]
        store, path = _tmp_store()
        md = generate_markdown_report(alerts, store)
        assert "# Wazuh Shift Report" in md
        path.unlink()

    def test_contains_status_table(self):
        alerts = [_make_alert("5710", "web-01")]
        store, path = _tmp_store()
        md = generate_markdown_report(alerts, store)
        for status in TriageStatus:
            assert status.label in md
        path.unlink()

    def test_total_count(self):
        alerts = [_make_alert("5710", "web-01"), _make_alert("5712", "db-01", level=12)]
        store, path = _tmp_store()
        md = generate_markdown_report(alerts, store)
        assert "2" in md  # total alerts
        path.unlink()

    def test_escalated_section(self):
        alert = _make_alert("5712", "db-01", level=12)
        store, path = _tmp_store()
        store.upsert(alert.alert_id, status=TriageStatus.ESCALATED, analyst="analyst1", notes="Bad actor")
        md = generate_markdown_report([alert], store)
        assert "Escalated" in md
        assert "db-01" in md
        path.unlink()

    def test_analyst_name_in_header(self):
        store, path = _tmp_store()
        md = generate_markdown_report([], store, analyst_name="Alice")
        assert "Alice" in md
        path.unlink()


class TestCSVReport:
    def test_has_header_row(self):
        store, path = _tmp_store()
        csv = generate_csv_report([], store)
        assert "alert_id" in csv
        assert "triage_status" in csv
        path.unlink()

    def test_one_row_per_alert(self):
        alerts = [_make_alert("5710", "web-01"), _make_alert("5712", "db-01")]
        store, path = _tmp_store()
        csv = generate_csv_report(alerts, store)
        lines = [l for l in csv.strip().splitlines() if l]
        assert len(lines) == 3  # header + 2 data rows
        path.unlink()

    def test_triage_status_in_row(self):
        alert = _make_alert("5710", "web-01")
        store, path = _tmp_store()
        store.upsert(alert.alert_id, status=TriageStatus.RESOLVED, analyst="bob", notes="Clean")
        csv = generate_csv_report([alert], store)
        assert "resolved" in csv
        assert "bob" in csv
        path.unlink()


class TestSaveReport:
    def test_saves_to_disk(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "reports" / "test.md"
            save_report("# hello", out)
            assert out.exists()
            assert out.read_text() == "# hello"
