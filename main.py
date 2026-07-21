#!/usr/bin/env python3
"""Wazuh Alert Viewer — punkt wejścia CLI."""

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
        description="Wazuh Alert Viewer — TUI do filtrowania, triage alertów i Decoder Lab",
    )
    parser.add_argument(
        "-a", "--alerts",
        type=Path,
        default=default_alerts_path(),
        help="Plik alertów (.json, .jsonl lub eksport OpenSearch)",
    )
    parser.add_argument(
        "-t", "--triage",
        type=Path,
        default=default_triage_path(),
        help="Plik JSON z statusami triage i notatkami",
    )
    # SSH / wazuh-logtest
    parser.add_argument(
        "--wazuh-host",
        default="",
        metavar="HOST",
        help="Adres IP/DNS Wazuh Managera (dla wazuh-logtest przez SSH)",
    )
    parser.add_argument(
        "--wazuh-user",
        default="root",
        metavar="USER",
        help="Użytkownik SSH (domyślnie: root)",
    )
    parser.add_argument(
        "--wazuh-port",
        type=int,
        default=22,
        metavar="PORT",
        help="Port SSH (domyślnie: 22)",
    )
    parser.add_argument(
        "--identity-file",
        default="",
        metavar="KEY",
        help="Klucz prywatny SSH (np. ~/.ssh/id_rsa)",
    )
    parser.add_argument(
        "--logtest-path",
        default="/var/ossec/bin/wazuh-logtest",
        metavar="PATH",
        help="Ścieżka do wazuh-logtest na zdalnym hoście",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if not args.alerts.exists():
        raise SystemExit(f"Nie znaleziono pliku alertów: {args.alerts}")

    ssh_cfg = WazuhSSHConfig(
        host=args.wazuh_host,
        user=args.wazuh_user,
        port=args.wazuh_port,
        identity_file=args.identity_file,
        logtest_path=args.logtest_path,
    )

    app = WazuhAlertViewer(
        alerts_path=args.alerts,
        triage_path=args.triage,
        ssh_cfg=ssh_cfg,
    )
    app.run()


if __name__ == "__main__":
    main()
