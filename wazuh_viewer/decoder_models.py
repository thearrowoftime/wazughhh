from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Raw log sample produced by the importer
# ---------------------------------------------------------------------------

@dataclass
class LogSample:
    raw: str
    source_file: str = ""
    line_number: int = 0
    # Pre-decoder fields extracted from syslog header
    timestamp: str = ""
    hostname: str = ""
    program_name: str = ""
    pid: str = ""
    message: str = ""      # body after syslog header
    syslog_format: str = ""  # "rfc3164" | "rfc5424" | "plain"


# ---------------------------------------------------------------------------
# Clustered group produced by Drain3
# ---------------------------------------------------------------------------

@dataclass
class LogCluster:
    cluster_id: int
    template: str          # Drain3 extracted template with <*> placeholders
    program_name: str = ""
    sample_count: int = 0
    samples: list[LogSample] = field(default_factory=list)
    # Populated after user selects cluster for generation
    generated_xml: str = ""
    generated_liblognorm: str = ""

    def representative(self) -> LogSample | None:
        return self.samples[0] if self.samples else None


# ---------------------------------------------------------------------------
# Result of running wazuh-logtest (local regex or remote SSH)
# ---------------------------------------------------------------------------

@dataclass
class LogtestPhase:
    name: str          # "Phase 1", "Phase 2", "Phase 3"
    fields: dict[str, str] = field(default_factory=dict)
    raw: str = ""


@dataclass
class LogtestResult:
    log: str
    success: bool
    phases: list[LogtestPhase] = field(default_factory=list)
    decoder_name: str = ""
    rule_id: str = ""
    rule_level: str = ""
    rule_description: str = ""
    raw_output: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Coverage report for a generated decoder against a set of samples
# ---------------------------------------------------------------------------

@dataclass
class CoverageReport:
    total: int = 0
    matched: int = 0
    unmatched_samples: list[str] = field(default_factory=list)

    @property
    def pct(self) -> float:
        if self.total == 0:
            return 0.0
        return self.matched / self.total * 100

    @property
    def label(self) -> str:
        return f"{self.matched}/{self.total} ({self.pct:.1f}%)"


# ---------------------------------------------------------------------------
# Wazuh SSH connection config (no secrets stored here)
# ---------------------------------------------------------------------------

@dataclass
class WazuhSSHConfig:
    host: str = ""
    user: str = "root"
    port: int = 22
    identity_file: str = ""
    logtest_path: str = "/var/ossec/bin/wazuh-logtest"

    def is_configured(self) -> bool:
        return bool(self.host.strip())
