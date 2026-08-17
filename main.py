#!/usr/bin/env python3
"""Wazuh Alert Viewer — CLI entry point."""

from __future__ import annotations

import argparse
from pathlib import Path

from wazuh_viewer.app import WazuhAlertViewer
from wazuh_viewer.decoder_models import WazuhSSHConfig


def default_alerts_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "sample_alerts.json"


def default_triage_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "triage_state.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Wazuh Alert Viewer — TUI for alert triage, filtering and Decoder Lab",
    )
    parser.add_argument(
        "-a", "--alerts",
        type=Path,
        default=default_alerts_path(),
        help="Alerts file (.json, .jsonl or OpenSearch export)",
    )
    parser.add_argument(
        "-t", "--triage",
        type=Path,
        default=default_triage_path(),
        help="JSON file to persist triage statuses and analyst notes",
    )
    # SSH / wazuh-logtest
    parser.add_argument(
        "--wazuh-host",
        default="",
        metavar="HOST",
        help="Wazuh Manager IP/DNS (for wazuh-logtest over SSH)",
    )
    parser.add_argument(
        "--wazuh-user",
        default="root",
        metavar="USER",
        help="SSH user (default: root)",
    )
    parser.add_argument(
        "--wazuh-port",
        type=int,
        default=22,
        metavar="PORT",
        help="SSH port (default: 22)",
    )
    parser.add_argument(
        "--identity-file",
        default="",
        metavar="KEY",
        help="SSH private key (e.g. ~/.ssh/id_rsa)",
    )
    parser.add_argument(
        "--logtest-path",
        default="/var/ossec/bin/wazuh-logtest",
        metavar="PATH",
        help="Path to wazuh-logtest on the remote host",
    )
    parser.add_argument(
        "--tab",
        choices=["alerts", "lab", "logtest"],
        default="alerts",
        help="Starting tab: alerts | lab | logtest (local decoder test)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.alerts.exists():
        raise SystemExit(f"Alerts file not found: {args.alerts}")

    ssh_cfg = WazuhSSHConfig(
        host=args.wazuh_host,
        user=args.wazuh_user,
        port=args.wazuh_port,
        identity_file=args.identity_file,
        logtest_path=args.logtest_path,
    )

    tab_ids = {"alerts": "tab-alerts", "lab": "tab-lab", "logtest": "tab-logtest"}
    app = WazuhAlertViewer(
        alerts_path=args.alerts,
        triage_path=args.triage,
        ssh_cfg=ssh_cfg,
        start_tab=tab_ids[args.tab],
    )
    app.run()


if __name__ == "__main__":
    main()
