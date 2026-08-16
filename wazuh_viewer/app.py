from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from wazuh_viewer.filters import (
    apply_filters,
    group_alerts,
    severity_options,
    triage_action_options,
    triage_filter_options,
    unique_hosts,
    unique_mitre_tags,
)
from wazuh_viewer.models import (
    Alert,
    AlertGroup,
    FilterState,
    SeverityBand,
    TriageStatus,
    severity_color,
    triage_color,
)
from wazuh_viewer.parser import load_alerts_from_file
from wazuh_viewer.storage import TriageStore
from wazuh_viewer.reporter import generate_markdown_report, generate_csv_report, save_report
from wazuh_viewer.decoder_models import LogCluster, LogSample, WazuhSSHConfig, CoverageReport
from wazuh_viewer.log_importer import load_samples, load_samples_from_dir
from wazuh_viewer.clusterer import cluster_samples
from wazuh_viewer.decoder_generator import (
    generate_wazuh_xml,
    generate_liblognorm,
    compute_local_coverage,
    _template_to_pcre2_and_order,
)
from wazuh_viewer.logtest_runner import run_logtest_ssh
from wazuh_viewer.local_logtest import DecoderXMLError, format_many, run_logtest
from wazuh_viewer.ssh_deployer import (
    check_connection,
    deploy_decoder_xml,
    deploy_liblognorm_rb,
    reload_wazuh_manager,
    run_logtest_check,
)
from wazuh_viewer.rsyslog_generator import (
    generate_rsyslog_conf,
    generate_liblognorm_bundle,
    generate_wazuh_xml_bundle,
)


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
    FilterPanel Select, FilterPanel Input, FilterPanel Checkbox {
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
    """Alert triage view — filter, deduplicate, inspect and annotate alerts."""

    DEFAULT_CSS = """
    AlertsTab #al-export-row {
        height: 3;
        padding: 0 1;
    }
    AlertsTab #al-export-row Button {
        margin-right: 1;
    }
    """

    def __init__(self, alerts_path: Path, triage_store: TriageStore, reports_dir: Path, **kwargs):
        super().__init__("Alerts", id="tab-alerts", **kwargs)
        self._alerts_path = alerts_path
        self._triage_store = triage_store
        self._reports_dir = reports_dir
        self._all_alerts: list[Alert] = []
        self._filtered_alerts: list[Alert] = []
        self._groups: list[AlertGroup] = []
        self._filters = FilterState()
        self._selected_id: str | None = None
        self._grouped_mode: bool = False
        self._window_minutes: int = 60

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
                yield Label("[b]Deduplication[/b]")
                yield Checkbox("Group by rule+host", id="al-group-toggle", value=False)
                yield Label("Time window (min)")
                yield Input(value="60", id="al-window-min")
                yield Label("[b]Export[/b]")
                yield Button("Markdown report", id="al-export-md", variant="success")
                yield Button("CSV export", id="al-export-csv", variant="success")
                yield Static("", id="al-export-status")
            with Vertical(id="al-table-panel"):
                yield DataTable(id="al-table", zebra_stripes=True)
            with Vertical():
                yield DetailPanel(id="al-detail")

    def on_mount(self) -> None:
        table = self.query_one("#al-table", DataTable)
        table.cursor_type = "row"
        self._set_table_columns(grouped=False)
        self.query_one("#al-detail", DetailPanel).mount(
            Static("[dim]Select an alert from the table[/dim]")
        )
        self.load_data()

    def _set_table_columns(self, grouped: bool) -> None:
        table = self.query_one("#al-table", DataTable)
        table.clear(columns=True)
        if grouped:
            table.add_columns("Count", "First seen", "Last seen", "Lvl", "Host", "Rule", "MITRE", "Description")
        else:
            table.add_columns("Time", "Lvl", "Host", "Rule", "MITRE", "Status", "Description")

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

        if self._grouped_mode:
            self._groups = group_alerts(self._filtered_alerts, self._window_minutes)
            for grp in self._groups:
                table.add_row(
                    str(grp.count),
                    grp.first_seen[:19].replace("T", " "),
                    grp.last_seen[:19].replace("T", " "),
                    str(grp.rule_level),
                    grp.host,
                    grp.rule_id,
                    grp.mitre_display,
                    grp.description[:55],
                    key=grp.group_key,
                )
            label = f"Groups: {len(self._groups)}"
        else:
            self._groups = []
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
            label = ""

        active = " [active]" if self._filters.is_active() else ""
        self.query_one("#al-summary", Static).update(
            f"\n[b]Results:[/b] {len(self._filtered_alerts)}/{len(self._all_alerts)}{active}"
            + (f"\n{label}" if label else "")
        )
        self.app.set_status(
            f"Showing {len(self._filtered_alerts)} of {len(self._all_alerts)} alerts"
        )

    def _update_filters(self, **kwargs) -> None:
        f = self._filters
        self._filters = FilterState(
            severity=kwargs.get("severity", f.severity),
            host=kwargs.get("host", f.host),
            mitre_tag=kwargs.get("mitre_tag", f.mitre_tag),
            triage_status=kwargs.get("triage_status", f.triage_status),
            search=kwargs.get("search", f.search),
        )
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

    @on(Checkbox.Changed, "#al-group-toggle")
    def _group_toggle(self, e: Checkbox.Changed) -> None:
        self._grouped_mode = e.value
        self._set_table_columns(grouped=self._grouped_mode)
        self._refresh_table()

    @on(Input.Changed, "#al-window-min")
    def _window_changed(self, e: Input.Changed) -> None:
        try:
            self._window_minutes = max(1, int(e.value))
            if self._grouped_mode:
                self._refresh_table()
        except ValueError:
            pass

    @on(DataTable.RowSelected, "#al-table")
    def _row_selected(self, e: DataTable.RowSelected) -> None:
        key = str(e.row_key.value)
        if self._grouped_mode:
            grp = next((g for g in self._groups if g.group_key == key), None)
            if grp:
                self._show_group_detail(grp)
        else:
            self._selected_id = key
            self._show_detail(key)

    def _show_group_detail(self, grp: AlertGroup) -> None:
        """Show summary detail for a deduplicated group."""
        panel = self.query_one("#al-detail", DetailPanel)
        panel.remove_children()
        sev = severity_color(grp.rule_level)
        lines = [
            Static(f"[b]Group:[/b] {grp.rule_id} @ {grp.host}"),
            Static(f"[{sev}]{grp.severity_label} (max level {grp.rule_level})[/{sev}]"),
            Static(f"[b]Count:[/b] {grp.count} events"),
            Static(f"[b]First seen:[/b] {grp.first_seen[:19].replace('T', ' ')}"),
            Static(f"[b]Last seen:[/b]  {grp.last_seen[:19].replace('T', ' ')}"),
            Static(f"[b]MITRE:[/b] {grp.mitre_display}"),
            Static(f"[b]Description:[/b] {grp.description}"),
            Static(f"[dim]Click individual alert to set triage — switch off grouping[/dim]"),
        ]
        if grp.count <= 5:
            lines.append(Static("\n[b]Individual events:[/b]"))
            for a in grp.alerts:
                lines.append(Static(f"  {a.timestamp[:19].replace('T',' ')} — {a.description[:60]}"))
        panel.mount(*lines)
        # Select the most recent alert so triage still works
        self._selected_id = grp.representative_id

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

    # ------------------------------------------------------------------
    # Export handlers
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#al-export-md")
    def _export_md(self) -> None:
        try:
            analyst = ""
            if self._selected_id:
                t = self._triage_store.get(self._selected_id)
                analyst = t.analyst
            md = generate_markdown_report(
                self._filtered_alerts,
                self._triage_store,
                analyst_name=analyst,
                shift_label=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            )
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            out = self._reports_dir / f"shift_report_{ts}.md"
            save_report(md, out)
            self.query_one("#al-export-status", Static).update(f"[green]Saved → {out.name}[/green]")
            self.app.set_status(f"Markdown report saved → {out}")
        except Exception as exc:
            self.query_one("#al-export-status", Static).update(f"[red]{exc}[/red]")

    @on(Button.Pressed, "#al-export-csv")
    def _export_csv(self) -> None:
        try:
            csv_data = generate_csv_report(self._filtered_alerts, self._triage_store)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            out = self._reports_dir / f"alerts_{ts}.csv"
            save_report(csv_data, out)
            self.query_one("#al-export-status", Static).update(f"[green]Saved → {out.name}[/green]")
            self.app.set_status(f"CSV saved → {out}")
        except Exception as exc:
            self.query_one("#al-export-status", Static).update(f"[red]{exc}[/red]")


# ============================================================================
# Decoder Lab Tab  (enhanced: batch export, auto-deploy, rsyslog conf)
# ============================================================================

class DecoderLabTab(TabPane):
    """Decoder Lab: import → cluster → generate → test → deploy."""

    DEFAULT_CSS = """
    DecoderLabTab { height: 1fr; }
    #lab-sidebar {
        width: 42;
        min-width: 36;
        border: solid $accent;
        padding: 1;
        background: $surface;
    }
    #lab-sidebar Label { margin-top: 1; }
    #lab-sidebar Input, #lab-sidebar Select, #lab-sidebar Button {
        width: 100%;
        margin-bottom: 1;
    }
    #lab-center { width: 1fr; border: solid $primary; padding: 1; }
    #lab-right {
        width: 54;
        min-width: 46;
        border: solid $accent-darken-2;
        padding: 1;
        background: $surface-darken-1;
    }
    #lab-cluster-table { height: 12; }
    #lab-coverage { margin-top: 1; }
    #lab-gen-xml { height: 12; }
    #lab-gen-rb  { height: 8; }
    #lab-rsyslog-conf { height: 8; }
    #lab-logtest-out { height: 10; }
    #lab-sample-detail { height: 8; }
    #lab-deploy-status { margin-top: 1; }
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

                yield Label("[b]SSH — Wazuh Manager[/b]")
                yield Input(placeholder="host IP / DNS", id="lab-ssh-host")
                yield Input(placeholder="user (default: root)", id="lab-ssh-user")
                yield Input(placeholder="port (default: 22)", id="lab-ssh-port")
                yield Input(placeholder="identity file ~/.ssh/id_rsa", id="lab-ssh-key")
                yield Button("Test connection", id="lab-ssh-test", variant="default")
                yield Static("", id="lab-ssh-status")

                yield Label("[b]Single cluster export[/b]")
                yield Button("Export XML", id="lab-export-xml", variant="success")
                yield Button("Export liblognorm", id="lab-export-rb", variant="success")
                yield Button("Deploy XML via SSH", id="lab-deploy-xml", variant="warning")

                yield Label("[b]Batch — all clusters[/b]")
                yield Button("Export ALL XML + liblognorm", id="lab-batch-export", variant="success")
                yield Button("Generate rsyslog .conf", id="lab-gen-rsyslog", variant="success")
                yield Input(placeholder="Wazuh host for rsyslog fwd (IP)", id="lab-rsyslog-host")
                yield Input(placeholder="Port (default 1514)", id="lab-rsyslog-port")
                yield Button("Deploy ALL + reload Wazuh", id="lab-deploy-all", variant="error")
                yield Static("", id="lab-deploy-status")

            with VerticalScroll(id="lab-center"):
                yield Static("[b]Log clusters[/b] — select a row to inspect")
                yield DataTable(id="lab-cluster-table", zebra_stripes=True)
                yield Static("", id="lab-coverage")

                yield Label("Wazuh decoder XML [dim](candidate — review before deploying)[/dim]")
                yield TextArea("", id="lab-gen-xml", language="xml")

                yield Label("liblognorm rulebase")
                yield TextArea("", id="lab-gen-rb")

                yield Label("rsyslog mmnormalize config [dim](batch, all clusters)[/dim]")
                yield TextArea("", id="lab-rsyslog-conf")

                yield Label("Representative sample")
                yield TextArea("", id="lab-sample-detail", read_only=True)

            with VerticalScroll(id="lab-right"):
                yield Static("[b]Pre-decoder output[/b]")
                yield Static("", id="lab-predecoder-info")
                yield Static("[b]Local logtest (no SSH)[/b]")
                yield Button("Test XML + sample locally", id="lab-local-logtest", variant="primary")
                yield Button("Test XML + all samples locally", id="lab-local-logtest-all", variant="default")
                yield Static("[b]wazuh-logtest (SSH)[/b]")
                yield Button("Run logtest (sample)", id="lab-run-logtest", variant="warning")
                yield Button("Run logtest (full cluster)", id="lab-run-logtest-all", variant="default")
                yield Button("Check deployed decoders", id="lab-logtest-check", variant="default")
                yield TextArea("", id="lab-logtest-out", read_only=True)
                yield Static("", id="lab-logtest-summary")

    def on_mount(self) -> None:
        table = self.query_one("#lab-cluster-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("ID", "Program", "Samples", "Coverage", "Template")

    # ------------------------------------------------------------------
    # Import
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
            self.app.call_from_thread(self._set_import_status, f"[yellow]Loading {path.name}…[/yellow]")
            samples = load_samples_from_dir(path) if is_dir else load_samples(path)
            clusters = cluster_samples(samples)
            self.app.call_from_thread(self._apply_import_result, samples, clusters)
        except Exception as exc:
            self.app.call_from_thread(self._set_import_status, f"[red]Import error: {exc}[/red]")

    def _apply_import_result(self, samples: list[LogSample], clusters: list[LogCluster]) -> None:
        self._samples = samples
        self._clusters = clusters
        self._selected_cluster = None
        self._populate_cluster_table()
        self._set_import_status(f"[green]{len(samples)} samples → {len(clusters)} clusters[/green]")
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
                c.template[:55],
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
            self.query_one("#lab-sample-detail", TextArea).load_text(
                f"raw:      {rep.raw}\n"
                f"format:   {rep.syslog_format}\n"
                f"ts:       {rep.timestamp}\n"
                f"host:     {rep.hostname}\n"
                f"program:  {rep.program_name}\n"
                f"pid:      {rep.pid}\n"
                f"message:  {rep.message}"
            )
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
        self._run_ssh_test_worker(cfg)

    @work(thread=True)
    def _run_ssh_test_worker(self, cfg: WazuhSSHConfig) -> None:
        r = check_connection(cfg, timeout=10)
        msg = f"[green]{r.message}[/green]" if r.success else f"[red]{r.message}[/red]"
        self.app.call_from_thread(self.query_one("#lab-ssh-status", Static).update, msg)

    # ------------------------------------------------------------------
    # Local logtest (no SSH)
    # ------------------------------------------------------------------

    def _lab_xml_and_logs(self, all_samples: bool) -> tuple[str, list[str]] | None:
        xml_text = self.query_one("#lab-gen-xml", TextArea).text.strip()
        if not xml_text:
            self.app.set_status("No decoder XML — select a cluster or paste XML first")
            return None
        if not self._selected_cluster:
            self.app.set_status("Select a cluster from the table")
            return None
        if all_samples:
            logs = [s.raw for s in self._selected_cluster.samples[:50]]
        else:
            rep = self._selected_cluster.representative()
            if not rep:
                self.app.set_status("Cluster has no samples")
                return None
            logs = [rep.raw]
        return xml_text, logs

    @on(Button.Pressed, "#lab-local-logtest")
    def _local_logtest_sample(self) -> None:
        payload = self._lab_xml_and_logs(all_samples=False)
        if payload:
            self._show_local_logtest(*payload)

    @on(Button.Pressed, "#lab-local-logtest-all")
    def _local_logtest_all(self) -> None:
        payload = self._lab_xml_and_logs(all_samples=True)
        if payload:
            self._show_local_logtest(*payload)

    def _show_local_logtest(self, xml_text: str, logs: list[str]) -> None:
        try:
            results = run_logtest(logs, xml_text=xml_text)
        except DecoderXMLError as exc:
            self.query_one("#lab-logtest-out", TextArea).load_text(f"ERROR: {exc}")
            self.query_one("#lab-logtest-summary", Static).update("[red]Invalid decoder XML[/red]")
            return
        out = format_many(results, debug=True)
        matched = sum(1 for r in results if r.matched)
        self.query_one("#lab-logtest-out", TextArea).load_text(out)
        color = "green" if matched == len(results) else "yellow" if matched else "red"
        self.query_one("#lab-logtest-summary", Static).update(
            f"[{color}]local logtest:[/] {matched}/{len(results)} decoder matched"
        )

    # ------------------------------------------------------------------
    # wazuh-logtest runners (SSH)
    # ------------------------------------------------------------------

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
        matched = sum(1 for r in results if r.decoder_name)
        parts = []
        for r in results[:10]:
            block = f"Log: {r.log[:80]}\n"
            if r.error:
                block += f"  ERROR: {r.error}\n"
            else:
                block += f"  Decoder: {r.decoder_name or '—'}  Rule: {r.rule_id or '—'} lvl={r.rule_level or '—'}\n"
                block += f"  {r.rule_description or ''}\n"
            parts.append(block)
        out = "\n".join(parts)
        if len(results) > 10:
            out += f"\n… (truncated, showing 10/{len(results)})"
        self.query_one("#lab-logtest-out", TextArea).load_text(out)
        self.query_one("#lab-logtest-summary", Static).update(
            f"[b]logtest coverage:[/b] {matched}/{len(results)} with decoder matched"
        )

    @on(Button.Pressed, "#lab-logtest-check")
    def _logtest_check(self) -> None:
        cfg = self._read_ssh_cfg()
        if not cfg.is_configured():
            self.app.set_status("Enter SSH credentials in the sidebar")
            return
        self.query_one("#lab-logtest-out", TextArea).load_text("[yellow]Checking deployed decoders…[/yellow]")
        self._run_logtest_check_worker(cfg)

    @work(thread=True)
    def _run_logtest_check_worker(self, cfg: WazuhSSHConfig) -> None:
        r = run_logtest_check(cfg)
        msg = f"[green]{r.message}[/green]" if r.success else f"[red]{r.message}[/red]"
        out = r.stdout or r.stderr or "(no output)"
        self.app.call_from_thread(self.query_one("#lab-logtest-out", TextArea).load_text, out)
        self.app.call_from_thread(self.query_one("#lab-logtest-summary", Static).update, msg)

    # ------------------------------------------------------------------
    # Single cluster export / deploy
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

    @on(Button.Pressed, "#lab-deploy-xml")
    def _deploy_xml(self) -> None:
        if not self._selected_cluster:
            self.app.set_status("Select a cluster first")
            return
        cfg = self._read_ssh_cfg()
        if not cfg.is_configured():
            self.app.set_status("Enter SSH credentials")
            return
        xml_text = self.query_one("#lab-gen-xml", TextArea).text
        prog = self._selected_cluster.program_name or "custom"
        filename = f"decoder_{prog.replace('/', '_')}.xml"
        self._set_deploy_status("[yellow]Deploying…[/yellow]")
        self._deploy_single_worker(xml_text, filename, cfg)

    @work(thread=True)
    def _deploy_single_worker(self, xml: str, filename: str, cfg: WazuhSSHConfig) -> None:
        r = deploy_decoder_xml(xml, filename, cfg)
        msg = f"[green]{r.message}[/green]" if r.success else f"[red]{r.message}[/red]"
        self.app.call_from_thread(self._set_deploy_status, msg)
        if r.success:
            self.app.call_from_thread(self.app.set_status, f"Deployed {filename} — run logtest check to validate")

    # ------------------------------------------------------------------
    # Batch export / rsyslog conf / deploy all
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#lab-batch-export")
    def _batch_export(self) -> None:
        if not self._clusters:
            self.app.set_status("No clusters loaded — import logs first")
            return
        try:
            self._generated_dir.mkdir(parents=True, exist_ok=True)
            xml_bundle = generate_wazuh_xml_bundle(self._clusters)
            rb_bundle = generate_liblognorm_bundle(self._clusters)
            for prog, xml in xml_bundle.items():
                safe = prog.replace("/", "_").replace(" ", "_")
                (self._generated_dir / f"decoder_{safe}.xml").write_text(xml, encoding="utf-8")
            for prog, rb in rb_bundle.items():
                safe = prog.replace("/", "_").replace(" ", "_")
                (self._generated_dir / f"{safe}.rb").write_text(rb, encoding="utf-8")
            self._set_deploy_status(
                f"[green]Exported {len(xml_bundle)} XML + {len(rb_bundle)} .rb → {self._generated_dir}[/green]"
            )
            self.app.set_status(f"Batch export: {len(xml_bundle)} decoders saved to {self._generated_dir}")
        except Exception as exc:
            self._set_deploy_status(f"[red]Export error: {exc}[/red]")

    @on(Button.Pressed, "#lab-gen-rsyslog")
    def _gen_rsyslog_conf(self) -> None:
        if not self._clusters:
            self.app.set_status("No clusters loaded")
            return
        wazuh_host = self.query_one("#lab-rsyslog-host", Input).value.strip() or "127.0.0.1"
        port_str = self.query_one("#lab-rsyslog-port", Input).value.strip()
        wazuh_port = int(port_str) if port_str.isdigit() else 1514
        conf = generate_rsyslog_conf(self._clusters, wazuh_host=wazuh_host, wazuh_port=wazuh_port)
        self.query_one("#lab-rsyslog-conf", TextArea).load_text(conf)
        # Save to disk
        self._generated_dir.mkdir(parents=True, exist_ok=True)
        out = self._generated_dir / "wazuh_forward.conf"
        out.write_text(conf, encoding="utf-8")
        self.app.set_status(f"rsyslog config saved → {out}")

    @on(Button.Pressed, "#lab-deploy-all")
    def _deploy_all(self) -> None:
        if not self._clusters:
            self.app.set_status("No clusters loaded")
            return
        cfg = self._read_ssh_cfg()
        if not cfg.is_configured():
            self.app.set_status("Enter SSH credentials")
            return
        self._set_deploy_status("[yellow]Deploying all decoders…[/yellow]")
        self._deploy_all_worker(cfg)

    @work(thread=True)
    def _deploy_all_worker(self, cfg: WazuhSSHConfig) -> None:
        xml_bundle = generate_wazuh_xml_bundle(self._clusters)
        results: list[str] = []
        ok_count = 0

        for prog, xml in xml_bundle.items():
            safe = prog.replace("/", "_").replace(" ", "_")
            filename = f"decoder_{safe}.xml"
            r = deploy_decoder_xml(xml, filename, cfg)
            if r.success:
                ok_count += 1
                results.append(f"✓ {filename}")
            else:
                results.append(f"✗ {filename}: {r.message}")

        # Validate syntax on remote
        check_r = run_logtest_check(cfg)
        if check_r.success:
            results.append(f"\n✓ Decoder syntax check: OK")
            # Only reload if syntax is clean
            reload_r = reload_wazuh_manager(cfg)
            if reload_r.success:
                results.append(f"✓ Wazuh Manager reloaded")
            else:
                results.append(f"✗ Reload failed: {reload_r.message}")
        else:
            results.append(f"\n✗ Syntax check FAILED — NOT reloading: {check_r.message}")

        summary = f"[green]Deployed {ok_count}/{len(xml_bundle)}[/green]"
        out_text = "\n".join(results)
        self.app.call_from_thread(self.query_one("#lab-logtest-out", TextArea).load_text, out_text)
        self.app.call_from_thread(self._set_deploy_status, summary)
        self.app.call_from_thread(
            self.app.set_status, f"Deploy complete: {ok_count}/{len(xml_bundle)} decoders"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_ssh_cfg(self) -> WazuhSSHConfig:
        host = self.query_one("#lab-ssh-host", Input).value.strip()
        user = self.query_one("#lab-ssh-user", Input).value.strip() or "root"
        port_str = self.query_one("#lab-ssh-port", Input).value.strip()
        port = int(port_str) if port_str.isdigit() else 22
        key = self.query_one("#lab-ssh-key", Input).value.strip()
        return WazuhSSHConfig(host=host, user=user, port=port, identity_file=key)

    def _set_import_status(self, msg: str) -> None:
        self.query_one("#lab-import-status", Static).update(msg)

    def _set_deploy_status(self, msg: str) -> None:
        self.query_one("#lab-deploy-status", Static).update(msg)


# ============================================================================
# Local Logtest Tab
# ============================================================================

_LT_SAMPLE_LOG = (
    "Jan  1 00:00:00 host example[123]: User 'admin' logged from '192.168.1.1'"
)

_LT_SAMPLE_XML = """\
<decoder name="example">
  <program_name>^example</program_name>
</decoder>

<decoder name="example">
  <parent>example</parent>
  <regex>User '(\\w+)' logged from '(\\d+.\\d+.\\d+.\\d+)'</regex>
  <order>user, srcip</order>
</decoder>
"""


class LogtestTab(TabPane):
    """Paste a log + decoder XML and see wazuh-logtest Phase 1/2 locally."""

    DEFAULT_CSS = """
    LogtestTab { height: 1fr; }
    LogtestTab #lt-help { padding: 0 1; height: 2; }
    LogtestTab #lt-toolbar {
        height: 3;
        padding: 0 1;
    }
    LogtestTab #lt-toolbar Input { width: 1fr; }
    LogtestTab #lt-toolbar Button { margin-left: 1; }
    LogtestTab #lt-status { padding: 0 1; height: 1; }
    LogtestTab #lt-mid { height: 1fr; }
    LogtestTab #lt-log-col, LogtestTab #lt-xml-col {
        width: 1fr;
        border: solid $accent;
        padding: 1;
    }
    LogtestTab #lt-log, LogtestTab #lt-xml { height: 1fr; }
    LogtestTab #lt-out-wrap {
        height: 1fr;
        border: solid $primary;
        padding: 1;
    }
    LogtestTab #lt-out { height: 1fr; }
    """

    def __init__(self, **kwargs):
        super().__init__("Logtest", id="tab-logtest", **kwargs)

    def compose(self) -> ComposeResult:
        yield Static(
            "[b]Local wazuh-logtest[/b]  — wklej log i XML dekodera. Bez SSH, bez menedżera.",
            id="lt-help",
        )
        with Horizontal(id="lt-toolbar"):
            yield Input(placeholder="ścieżka do decoder.xml albo folderu z *.xml", id="lt-path")
            yield Button("Wczytaj XML", id="lt-load")
            yield Button("Testuj log", id="lt-run", variant="primary")
        yield Static("Gotowy przykład w edytorze — kliknij Testuj log", id="lt-status")
        with Horizontal(id="lt-mid"):
            with Vertical(id="lt-log-col"):
                yield Label("Log (jedna linia = jedno zdarzenie)")
                yield TextArea(_LT_SAMPLE_LOG, id="lt-log")
            with Vertical(id="lt-xml-col"):
                yield Label("Decoder XML")
                yield TextArea(_LT_SAMPLE_XML, id="lt-xml", language="xml")
        with Vertical(id="lt-out-wrap"):
            yield Label("Wynik (Phase 1 pre-decoding + Phase 2 decoding)")
            yield TextArea("", id="lt-out", read_only=True)

    @on(Button.Pressed, "#lt-load")
    def _load_xml(self) -> None:
        path_str = self.query_one("#lt-path", Input).value.strip()
        if not path_str:
            self.query_one("#lt-status", Static).update("[red]Podaj ścieżkę do pliku lub folderu XML[/red]")
            return
        p = Path(path_str)
        if not p.exists():
            self.query_one("#lt-status", Static).update(f"[red]Nie znaleziono: {p}[/red]")
            return
        try:
            if p.is_dir():
                chunks = []
                files = sorted(p.glob("*.xml"))
                if not files:
                    self.query_one("#lt-status", Static).update(f"[red]Brak plików .xml w {p}[/red]")
                    return
                for xml_file in files:
                    chunks.append(f"<!-- {xml_file.name} -->\n{xml_file.read_text(encoding='utf-8', errors='replace')}")
                text = "\n\n".join(chunks)
                self.query_one("#lt-status", Static).update(
                    f"[green]Wczytano {len(files)} plików XML z {p.name}[/green]"
                )
            else:
                text = p.read_text(encoding="utf-8", errors="replace")
                self.query_one("#lt-status", Static).update(f"[green]Wczytano {p.name}[/green]")
            self.query_one("#lt-xml", TextArea).load_text(text)
        except OSError as exc:
            self.query_one("#lt-status", Static).update(f"[red]{exc}[/red]")

    @on(Button.Pressed, "#lt-run")
    def _run(self) -> None:
        xml_text = self.query_one("#lt-xml", TextArea).text
        log_text = self.query_one("#lt-log", TextArea).text
        logs = [ln for ln in log_text.splitlines() if ln.strip()]
        if not logs:
            self.query_one("#lt-status", Static).update("[red]Wklej przynajmniej jedną linię logu[/red]")
            return
        try:
            results = run_logtest(logs, xml_text=xml_text)
        except DecoderXMLError as exc:
            self.query_one("#lt-out", TextArea).load_text(f"ERROR: {exc}")
            self.query_one("#lt-status", Static).update("[red]Niepoprawny XML dekodera[/red]")
            return
        out = format_many(results, debug=True)
        matched = sum(1 for r in results if r.matched)
        self.query_one("#lt-out", TextArea).load_text(out)
        color = "green" if matched == len(results) else "yellow" if matched else "red"
        self.query_one("#lt-status", Static).update(
            f"[{color}]{matched}/{len(results)} logów z dopasowanym dekoderem[/]"
        )
        self.app.set_status(f"Local logtest: {matched}/{len(results)} matched")


# ============================================================================
# Main App
# ============================================================================

class WazuhAlertViewer(App):
    TITLE = "Wazuh Alert Viewer"
    SUB_TITLE = "Alert Triage, Decoder Lab & Local Logtest"

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
        Binding("3", "switch_tab('tab-logtest')", "Logtest"),
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
        start_tab: str = "tab-alerts",
    ) -> None:
        super().__init__()
        self._alerts_path = alerts_path
        self._triage_store = TriageStore(triage_path)
        self._ssh_cfg = ssh_cfg or WazuhSSHConfig()
        self._generated_dir = alerts_path.parent / "generated"
        self._reports_dir = alerts_path.parent / "reports"
        self._start_tab = start_tab

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            yield AlertsTab(self._alerts_path, self._triage_store, self._reports_dir)
            yield DecoderLabTab(self._ssh_cfg, self._generated_dir)
            yield LogtestTab()
        yield Static("Ready", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        if self._start_tab:
            self.query_one(TabbedContent).active = self._start_tab

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
