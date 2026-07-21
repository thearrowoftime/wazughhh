from __future__ import annotations

import re
import json
from pathlib import Path
from typing import cast

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
    Tab,
    TabbedContent,
    TabPane,
    TextArea,
)

from wazuh_viewer.filters import (
    apply_filters,
    severity_options,
    triage_action_options,
    triage_filter_options,
    unique_hosts,
    unique_mitre_tags,
)
from wazuh_viewer.models import (
    Alert,
    FilterState,
    SeverityBand,
    TriageStatus,
    severity_color,
    triage_color,
)
from wazuh_viewer.parser import load_alerts_from_file
from wazuh_viewer.storage import TriageStore
from wazuh_viewer.decoder_models import (
    LogCluster,
    LogSample,
    WazuhSSHConfig,
    CoverageReport,
)
from wazuh_viewer.log_importer import load_samples, load_samples_from_dir
from wazuh_viewer.clusterer import cluster_samples
from wazuh_viewer.decoder_generator import (
    generate_wazuh_xml,
    generate_liblognorm,
    compute_local_coverage,
    _template_to_pcre2_and_order,
)
from wazuh_viewer.logtest_runner import run_logtest_ssh


# ============================================================================
# Shared helper widgets
# ============================================================================

class FilterPanel(Vertical):
    DEFAULT_CSS = """
    FilterPanel {
        width: 34;
        min-width: 30;
        border: solid $accent;
        padding: 1;
        background: $surface;
    }
    FilterPanel Label { margin-top: 1; }
    FilterPanel Select, FilterPanel Input {
        width: 100%;
        margin-bottom: 1;
    }
    """


class DetailPanel(VerticalScroll):
    DEFAULT_CSS = """
    DetailPanel {
        height: 1fr;
        border: solid $accent-darken-2;
        padding: 1;
        background: $surface-darken-1;
    }
    DetailPanel TextArea { height: 8; margin-top: 1; }
    DetailPanel Input { margin-top: 1; }
    DetailPanel Select { margin-top: 1; width: 100%; }
    """


# ============================================================================
# Alert Triage Tab
# ============================================================================

class AlertsTab(TabPane):
    """Alert triage view — filter, inspect, and annotate Wazuh alerts."""

    def __init__(self, alerts_path: Path, triage_store: TriageStore, **kwargs):
        super().__init__("Alerts", id="tab-alerts", **kwargs)
        self._alerts_path = alerts_path
        self._triage_store = triage_store
        self._all_alerts: list[Alert] = []
        self._filtered_alerts: list[Alert] = []
        self._filters = FilterState()
        self._selected_id: str | None = None

    def compose(self) -> ComposeResult:
        with Horizontal():
            with FilterPanel():
                yield Label("[b]Filters[/b]")
                yield Label("Severity")
                yield Select(severity_options(), id="al-sev", value=SeverityBand.ALL.value)
                yield Label("Host")
                yield Select([("", "All hosts")], id="al-host", value="", allow_blank=True)
                yield Label("MITRE tag")
                yield Select([("", "All tags")], id="al-mitre", value="", allow_blank=True)
                yield Label("Triage status")
                yield Select(triage_filter_options(), id="al-triage", value="all")
                yield Label("Search")
                yield Input(placeholder="description, rule, note…", id="al-search")
                yield Static("", id="al-summary")
            with Vertical(id="al-table-panel"):
                yield DataTable(id="al-table", zebra_stripes=True)
            with Vertical():
                yield DetailPanel(id="al-detail")

    def on_mount(self) -> None:
        table = self.query_one("#al-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Time", "Lvl", "Host", "Rule", "MITRE", "Status", "Description")
        self.query_one("#al-detail", DetailPanel).mount(
            Static("[dim]Select an alert from the table[/dim]")
        )
        self.load_data()

    def load_data(self) -> None:
        try:
            self._all_alerts = load_alerts_from_file(self._alerts_path)
            self._populate_selects()
            self._refresh_table()
            self.app.set_status(
                f"Loaded {len(self._all_alerts)} alerts from {self._alerts_path.name}"
            )
        except Exception as exc:
            self.app.set_status(f"Error loading alerts: {exc}")

    def _populate_selects(self) -> None:
        host_s = self.query_one("#al-host", Select)
        host_s.set_options([("", "All hosts")] + [(h, h) for h in unique_hosts(self._all_alerts)])
        mitre_s = self.query_one("#al-mitre", Select)
        mitre_s.set_options([("", "All tags")] + [(t, t) for t in unique_mitre_tags(self._all_alerts)])

    def _refresh_table(self) -> None:
        self._filtered_alerts = apply_filters(self._all_alerts, self._filters, self._triage_store)
        table = self.query_one("#al-table", DataTable)
        table.clear()
        for alert in self._filtered_alerts:
            triage = self._triage_store.get(alert.alert_id)
            table.add_row(
                alert.timestamp[:19].replace("T", " "),
                str(alert.rule_level),
                alert.host,
                alert.rule_id,
                alert.mitre_display,
                triage.status.label,
                alert.description[:60],
                key=alert.alert_id,
            )
        active = " [active]" if self._filters.is_active() else ""
        self.query_one("#al-summary", Static).update(
            f"\n[b]Results:[/b] {len(self._filtered_alerts)}/{len(self._all_alerts)}{active}"
        )
        self.app.set_status(
            f"Showing {len(self._filtered_alerts)} of {len(self._all_alerts)} alerts"
        )

    def _update_filters(self, **kwargs) -> None:
        f = self._filters
        new_f = FilterState(
            severity=kwargs.get("severity", f.severity),
            host=kwargs.get("host", f.host),
            mitre_tag=kwargs.get("mitre_tag", f.mitre_tag),
            triage_status=kwargs.get("triage_status", f.triage_status),
            search=kwargs.get("search", f.search),
        )
        self._filters = new_f
        self._refresh_table()

    @on(Select.Changed, "#al-sev")
    def _sev(self, e: Select.Changed) -> None:
        self._update_filters(severity=SeverityBand(e.value))

    @on(Select.Changed, "#al-host")
    def _host(self, e: Select.Changed) -> None:
        self._update_filters(host=str(e.value or ""))

    @on(Select.Changed, "#al-mitre")
    def _mitre(self, e: Select.Changed) -> None:
        self._update_filters(mitre_tag=str(e.value or ""))

    @on(Select.Changed, "#al-triage")
    def _triage_flt(self, e: Select.Changed) -> None:
        self._update_filters(triage_status=str(e.value))

    @on(Input.Changed, "#al-search")
    def _search(self, e: Input.Changed) -> None:
        self._update_filters(search=e.value)

    @on(DataTable.RowSelected, "#al-table")
    def _row_selected(self, e: DataTable.RowSelected) -> None:
        self._selected_id = str(e.row_key.value)
        self._show_detail(self._selected_id)

    def _show_detail(self, alert_id: str) -> None:
        alert = next(
            (a for a in self._filtered_alerts + self._all_alerts if a.alert_id == alert_id),
            None,
        )
        if not alert:
            return
        triage = self._triage_store.get(alert_id)
        panel = self.query_one("#al-detail", DetailPanel)
        panel.remove_children()
        sev = severity_color(alert.rule_level)
        tri = triage_color(triage.status)
        panel.mount(
            Static(f"[b]Alert[/b] {alert.alert_id}"),
            Static(f"[{sev}]Severity {alert.rule_level} ({alert.severity_label})[/{sev}]"),
            Static(f"[b]Host:[/b] {alert.host}  [b]Agent:[/b] {alert.agent_id}"),
            Static(f"[b]Rule:[/b] {alert.rule_id}"),
            Static(f"[b]Time:[/b] {alert.timestamp}"),
            Static(f"[b]MITRE:[/b] {alert.mitre_display}"),
            Static(
                f"[b]Tactics:[/b] {', '.join(alert.mitre_tactics) or '—'}  "
                f"[b]Techniques:[/b] {', '.join(alert.mitre_techniques) or '—'}"
            ),
            Static(f"[b]Description:[/b] {alert.description}"),
            Static(f"[{tri}][b]Triage status:[/b] {triage.status.label}[/{tri}]"),
            Label("Triage status"),
            Select(triage_action_options(), id="al-det-status", value=triage.status.value),
            Label("Analyst"),
            Input(value=triage.analyst, placeholder="e.g. john.doe", id="al-det-analyst"),
            Label("Analyst notes"),
            TextArea(triage.notes, id="al-det-notes"),
            Static(
                f"[dim]Last updated: {triage.updated_at or 'never'}[/dim]",
                id="al-det-updated",
            ),
        )

    @on(Select.Changed, "#al-det-status")
    def _det_status(self, e: Select.Changed) -> None:
        if not self._selected_id:
            return
        self._triage_store.upsert(self._selected_id, status=TriageStatus(str(e.value)))
        self._refresh_table()
        self.app.set_status(f"Status: {TriageStatus(str(e.value)).label}")

    def save_triage(self) -> None:
        if not self._selected_id:
            self.app.set_status("Select an alert from the table first")
            return
        try:
            analyst = self.query_one("#al-det-analyst", Input).value
            notes = self.query_one("#al-det-notes", TextArea).text
            status = TriageStatus(str(self.query_one("#al-det-status", Select).value))
            t = self._triage_store.upsert(self._selected_id, status=status, analyst=analyst, notes=notes)
            self.query_one("#al-det-updated", Static).update(
                f"[dim]Last updated: {t.updated_at}[/dim]"
            )
            self._refresh_table()
            self.app.set_status("Triage saved")
        except Exception:
            self.app.set_status("No detail panel open — select an alert first")

    def clear_selection(self) -> None:
        self._selected_id = None
        panel = self.query_one("#al-detail", DetailPanel)
        panel.remove_children()
        panel.mount(Static("[dim]Select an alert from the table[/dim]"))


# ============================================================================
# Decoder Lab Tab
# ============================================================================

class DecoderLabTab(TabPane):
    """Decoder Lab: import → cluster → generate → test → export."""

    DEFAULT_CSS = """
    DecoderLabTab {
        height: 1fr;
    }
    #lab-sidebar {
        width: 40;
        min-width: 34;
        border: solid $accent;
        padding: 1;
        background: $surface;
    }
    #lab-sidebar Label { margin-top: 1; }
    #lab-sidebar Input, #lab-sidebar Select, #lab-sidebar Button {
        width: 100%;
        margin-bottom: 1;
    }
    #lab-center {
        width: 1fr;
        border: solid $primary;
        padding: 1;
    }
    #lab-right {
        width: 52;
        min-width: 44;
        border: solid $accent-darken-2;
        padding: 1;
        background: $surface-darken-1;
    }
    #lab-cluster-table { height: 14; }
    #lab-coverage { margin-top: 1; }
    #lab-gen-xml { height: 14; }
    #lab-gen-rb  { height: 9; }
    #lab-logtest-out { height: 12; }
    #lab-sample-detail { height: 10; }
    """

    def __init__(self, ssh_cfg: WazuhSSHConfig, generated_dir: Path, **kwargs):
        super().__init__("Decoder Lab", id="tab-lab", **kwargs)
        self._ssh_cfg = ssh_cfg
        self._generated_dir = generated_dir
        self._samples: list[LogSample] = []
        self._clusters: list[LogCluster] = []
        self._selected_cluster: LogCluster | None = None

    def compose(self) -> ComposeResult:
        with Horizontal():
            with Vertical(id="lab-sidebar"):
                yield Label("[b]Import logs[/b]")
                yield Input(placeholder="path to .log / .txt / .jsonl / .json", id="lab-path")
                yield Button("Load file", id="lab-load-file", variant="primary")
                yield Button("Load directory", id="lab-load-dir", variant="default")
                yield Static("", id="lab-import-status")

                yield Label("[b]SSH (wazuh-logtest)[/b]")
                yield Input(placeholder="host IP / DNS", id="lab-ssh-host")
                yield Input(placeholder="user (default: root)", id="lab-ssh-user")
                yield Input(placeholder="port (default: 22)", id="lab-ssh-port")
                yield Input(placeholder="identity file ~/.ssh/id_rsa", id="lab-ssh-key")
                yield Button("Test SSH", id="lab-ssh-test", variant="default")
                yield Static("", id="lab-ssh-status")

                yield Button("Export XML", id="lab-export-xml", variant="success")
                yield Button("Export liblognorm", id="lab-export-rb", variant="success")

            with VerticalScroll(id="lab-center"):
                yield Static("[b]Log clusters[/b] — select a row to inspect")
                yield DataTable(id="lab-cluster-table", zebra_stripes=True)
                yield Static("", id="lab-coverage")

                yield Label("Wazuh decoder XML [dim](candidate — review before deploying)[/dim]")
                yield TextArea("", id="lab-gen-xml", language="xml")

                yield Label("liblognorm rulebase")
                yield TextArea("", id="lab-gen-rb")

                yield Label("Representative sample")
                yield TextArea("", id="lab-sample-detail", read_only=True)

            with VerticalScroll(id="lab-right"):
                yield Static("[b]Pre-decoder output[/b]")
                yield Static("", id="lab-predecoder-info")
                yield Static("[b]wazuh-logtest result (SSH)[/b]")
                yield Button("Run logtest (sample)", id="lab-run-logtest", variant="warning")
                yield Button("Run logtest (full cluster)", id="lab-run-logtest-all", variant="default")
                yield TextArea("", id="lab-logtest-out", read_only=True)
                yield Static("", id="lab-logtest-summary")

    def on_mount(self) -> None:
        table = self.query_one("#lab-cluster-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("ID", "Program", "Samples", "Coverage", "Template")

    # ------------------------------------------------------------------
    # Import handlers
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#lab-load-file")
    def _load_file(self) -> None:
        path_str = self.query_one("#lab-path", Input).value.strip()
        if not path_str:
            self._set_import_status("[red]Enter a file path[/red]")
            return
        p = Path(path_str)
        if not p.exists():
            self._set_import_status(f"[red]File not found: {p}[/red]")
            return
        self._do_import(p, is_dir=False)

    @on(Button.Pressed, "#lab-load-dir")
    def _load_dir(self) -> None:
        path_str = self.query_one("#lab-path", Input).value.strip()
        if not path_str:
            self._set_import_status("[red]Enter a directory path[/red]")
            return
        p = Path(path_str)
        if not p.is_dir():
            self._set_import_status(f"[red]Not a directory: {p}[/red]")
            return
        self._do_import(p, is_dir=True)

    @work(thread=True)
    def _do_import(self, path: Path, is_dir: bool) -> None:
        try:
            self.app.call_from_thread(
                self._set_import_status, f"[yellow]Loading {path.name}…[/yellow]"
            )
            if is_dir:
                samples = load_samples_from_dir(path)
            else:
                samples = load_samples(path)

            clusters = cluster_samples(samples)
            self.app.call_from_thread(self._apply_import_result, samples, clusters)
        except Exception as exc:
            self.app.call_from_thread(
                self._set_import_status, f"[red]Import error: {exc}[/red]"
            )

    def _apply_import_result(self, samples: list[LogSample], clusters: list[LogCluster]) -> None:
        self._samples = samples
        self._clusters = clusters
        self._selected_cluster = None
        self._populate_cluster_table()
        self._set_import_status(
            f"[green]{len(samples)} samples → {len(clusters)} clusters[/green]"
        )
        self.app.set_status(f"Decoder Lab: {len(samples)} samples, {len(clusters)} clusters")

    def _populate_cluster_table(self) -> None:
        table = self.query_one("#lab-cluster-table", DataTable)
        table.clear()
        for c in self._clusters:
            regex, _ = _template_to_pcre2_and_order(c.template)
            cov = compute_local_coverage(c, regex)
            table.add_row(
                str(c.cluster_id),
                c.program_name[:20],
                str(c.sample_count),
                cov.label,
                c.template[:60],
                key=str(c.cluster_id),
            )

    # ------------------------------------------------------------------
    # Cluster selection
    # ------------------------------------------------------------------

    @on(DataTable.RowSelected, "#lab-cluster-table")
    def _cluster_selected(self, e: DataTable.RowSelected) -> None:
        cid = int(str(e.row_key.value))
        cluster = next((c for c in self._clusters if c.cluster_id == cid), None)
        if not cluster:
            return
        self._selected_cluster = cluster
        self._show_cluster_detail(cluster)

    def _show_cluster_detail(self, cluster: LogCluster) -> None:
        xml_text = generate_wazuh_xml(cluster)
        rb_text = generate_liblognorm(cluster)

        cluster.generated_xml = xml_text
        cluster.generated_liblognorm = rb_text

        self.query_one("#lab-gen-xml", TextArea).load_text(xml_text)
        self.query_one("#lab-gen-rb", TextArea).load_text(rb_text)

        regex, _ = _template_to_pcre2_and_order(cluster.template)
        cov = compute_local_coverage(cluster, regex)
        cov_markup = f"[b]Local coverage:[/b] {cov.label}"
        if cov.unmatched_samples:
            cov_markup += "  [dim](unmatched samples shown below)[/dim]"
        self.query_one("#lab-coverage", Static).update(cov_markup)

        rep = cluster.representative()
        if rep:
            sample_text = (
                f"raw:      {rep.raw}\n"
                f"format:   {rep.syslog_format}\n"
                f"ts:       {rep.timestamp}\n"
                f"host:     {rep.hostname}\n"
                f"program:  {rep.program_name}\n"
                f"pid:      {rep.pid}\n"
                f"message:  {rep.message}"
            )
            self.query_one("#lab-sample-detail", TextArea).load_text(sample_text)
            predecoder_markup = (
                f"[b]Format:[/b] {rep.syslog_format}\n"
                f"[b]Timestamp:[/b] {rep.timestamp}\n"
                f"[b]Hostname:[/b] {rep.hostname}\n"
                f"[b]Program:[/b] {rep.program_name}\n"
                f"[b]PID:[/b] {rep.pid}\n"
                f"[b]Message:[/b] {rep.message[:120]}"
            )
            if cov.unmatched_samples:
                predecoder_markup += f"\n\n[b]Unmatched ({len(cov.unmatched_samples)}):[/b]\n"
                predecoder_markup += "\n".join(cov.unmatched_samples[:3])
        else:
            predecoder_markup = "[dim]no samples[/dim]"
            self.query_one("#lab-sample-detail", TextArea).load_text("")

        self.query_one("#lab-predecoder-info", Static).update(predecoder_markup)
        self.query_one("#lab-logtest-out", TextArea).load_text("")
        self.query_one("#lab-logtest-summary", Static).update("")

    # ------------------------------------------------------------------
    # SSH test
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#lab-ssh-test")
    def _ssh_test(self) -> None:
        cfg = self._read_ssh_cfg()
        if not cfg.is_configured():
            self.query_one("#lab-ssh-status", Static).update("[red]Enter a host address[/red]")
            return
        self.query_one("#lab-ssh-status", Static).update("[yellow]Connecting…[/yellow]")
        self._run_ssh_test(cfg)

    @work(thread=True)
    def _run_ssh_test(self, cfg: WazuhSSHConfig) -> None:
        results = run_logtest_ssh(["Jul 21 10:00:01 host sshd[1]: test message"], cfg, timeout=10)
        r = results[0]
        if r.error and "not found" not in r.error.lower():
            msg = f"[red]SSH error: {r.error}[/red]"
        else:
            msg = "[green]SSH OK — wazuh-logtest is reachable[/green]"
        self.app.call_from_thread(
            self.query_one("#lab-ssh-status", Static).update, msg
        )

    @on(Button.Pressed, "#lab-run-logtest")
    def _run_logtest_single(self) -> None:
        if not self._selected_cluster:
            self.app.set_status("Select a cluster from the table")
            return
        rep = self._selected_cluster.representative()
        if not rep:
            self.app.set_status("Cluster has no samples")
            return
        cfg = self._read_ssh_cfg()
        if not cfg.is_configured():
            self.app.set_status("Enter SSH credentials in the sidebar")
            return
        self.query_one("#lab-logtest-out", TextArea).load_text("[yellow]Running…[/yellow]")
        self._run_logtest_worker([rep.raw], cfg)

    @on(Button.Pressed, "#lab-run-logtest-all")
    def _run_logtest_all(self) -> None:
        if not self._selected_cluster:
            self.app.set_status("Select a cluster from the table")
            return
        cfg = self._read_ssh_cfg()
        if not cfg.is_configured():
            self.app.set_status("Enter SSH credentials in the sidebar")
            return
        samples = [s.raw for s in self._selected_cluster.samples[:50]]
        self.query_one("#lab-logtest-out", TextArea).load_text(
            f"[yellow]Sending {len(samples)} samples…[/yellow]"
        )
        self._run_logtest_worker(samples, cfg)

    @work(thread=True)
    def _run_logtest_worker(self, samples: list[str], cfg: WazuhSSHConfig) -> None:
        results = run_logtest_ssh(samples, cfg)
        self.app.call_from_thread(self._show_logtest_results, results)

    def _show_logtest_results(self, results) -> None:
        if not results:
            self.query_one("#lab-logtest-out", TextArea).load_text("No results")
            return
        parts: list[str] = []
        matched = sum(1 for r in results if r.decoder_name)
        for r in results[:10]:
            block = f"Log: {r.log[:80]}\n"
            if r.error:
                block += f"  ERROR: {r.error}\n"
            else:
                block += f"  Decoder: {r.decoder_name or '—'}  Rule: {r.rule_id or '—'} lvl={r.rule_level or '—'}\n"
                block += f"  {r.rule_description or ''}\n"
            parts.append(block)

        out_text = "\n".join(parts)
        if len(results) > 10:
            out_text += f"\n… (truncated, showing 10/{len(results)})"

        self.query_one("#lab-logtest-out", TextArea).load_text(out_text)
        total = len(results)
        self.query_one("#lab-logtest-summary", Static).update(
            f"[b]logtest coverage:[/b] {matched}/{total} with decoder matched"
        )

    def _read_ssh_cfg(self) -> WazuhSSHConfig:
        host = self.query_one("#lab-ssh-host", Input).value.strip()
        user = self.query_one("#lab-ssh-user", Input).value.strip() or "root"
        port_str = self.query_one("#lab-ssh-port", Input).value.strip()
        port = int(port_str) if port_str.isdigit() else 22
        key = self.query_one("#lab-ssh-key", Input).value.strip()
        return WazuhSSHConfig(host=host, user=user, port=port, identity_file=key)

    # ------------------------------------------------------------------
    # Export handlers
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#lab-export-xml")
    def _export_xml(self) -> None:
        if not self._selected_cluster:
            self.app.set_status("Select a cluster before exporting")
            return
        xml_text = self.query_one("#lab-gen-xml", TextArea).text
        prog = self._selected_cluster.program_name or "custom"
        out = self._generated_dir / f"decoder_{prog.replace('/', '_')}.xml"
        self._generated_dir.mkdir(parents=True, exist_ok=True)
        out.write_text(xml_text, encoding="utf-8")
        self.app.set_status(f"Saved XML → {out}")

    @on(Button.Pressed, "#lab-export-rb")
    def _export_rb(self) -> None:
        if not self._selected_cluster:
            self.app.set_status("Select a cluster before exporting")
            return
        rb_text = self.query_one("#lab-gen-rb", TextArea).text
        prog = self._selected_cluster.program_name or "custom"
        out = self._generated_dir / f"{prog.replace('/', '_')}.rb"
        self._generated_dir.mkdir(parents=True, exist_ok=True)
        out.write_text(rb_text, encoding="utf-8")
        self.app.set_status(f"Saved rulebase → {out}")

    def _set_import_status(self, msg: str) -> None:
        self.query_one("#lab-import-status", Static).update(msg)


# ============================================================================
# Main App — two tabs
# ============================================================================

class WazuhAlertViewer(App):
    TITLE = "Wazuh Alert Viewer"
    SUB_TITLE = "Alert Triage & Decoder Lab"

    CSS = """
    Screen { layout: vertical; }
    TabbedContent { height: 1fr; }
    TabPane { height: 1fr; padding: 0; }
    #tab-alerts > Horizontal { height: 1fr; }
    #tab-alerts #al-table-panel { width: 1fr; border: solid $primary; }
    #tab-alerts DataTable { height: 1fr; }
    #tab-alerts #al-detail { height: 1fr; width: 48; min-width: 40; }
    #status-bar {
        dock: bottom;
        height: 1;
        background: $accent;
        color: $text;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("1", "switch_tab('tab-alerts')", "Alerts"),
        Binding("2", "switch_tab('tab-lab')", "Decoder Lab"),
        Binding("r", "reload", "Reload"),
        Binding("s", "save_triage", "Save triage"),
        Binding("/", "focus_search", "Search"),
        Binding("escape", "clear_sel", "Clear"),
    ]

    def __init__(
        self,
        alerts_path: Path,
        triage_path: Path,
        ssh_cfg: WazuhSSHConfig | None = None,
    ) -> None:
        super().__init__()
        self._alerts_path = alerts_path
        self._triage_store = TriageStore(triage_path)
        self._ssh_cfg = ssh_cfg or WazuhSSHConfig()
        self._generated_dir = alerts_path.parent / "generated"

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            yield AlertsTab(self._alerts_path, self._triage_store)
            yield DecoderLabTab(self._ssh_cfg, self._generated_dir)
        yield Static("Ready", id="status-bar")
        yield Footer()

    def set_status(self, msg: str) -> None:
        self.query_one("#status-bar", Static).update(msg)

    def action_switch_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def action_reload(self) -> None:
        try:
            tab = self.query_one(AlertsTab)
            self._triage_store.load()
            tab.load_data()
        except Exception:
            pass

    def action_save_triage(self) -> None:
        try:
            self.query_one(AlertsTab).save_triage()
        except Exception:
            pass

    def action_focus_search(self) -> None:
        try:
            self.query_one("#al-search", Input).focus()
        except Exception:
            pass

    def action_clear_sel(self) -> None:
        try:
            self.query_one(AlertsTab).clear_selection()
        except Exception:
            pass
