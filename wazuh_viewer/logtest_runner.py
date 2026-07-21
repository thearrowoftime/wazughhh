"""
Run wazuh-logtest on a remote Wazuh Manager via system SSH (no shell=True).
Parses the three-phase output into structured LogtestResult objects.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from wazuh_viewer.decoder_models import LogtestPhase, LogtestResult, WazuhSSHConfig


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------

# Matches: "**Phase 1: Completed pre-decoding." or "**Phase 1: ...**"
_PHASE_RE = re.compile(r"^\*+\s*(Phase \d+.*?)[\*\s]*$")
_FIELD_RE = re.compile(r"^\s+(.+?):\s+(.+)$")
_DECODER_RE = re.compile(r"decoder:\s+'(.+)'", re.IGNORECASE)
_RULE_ID_RE = re.compile(r"id:\s+'(\d+)'", re.IGNORECASE)
_RULE_LEVEL_RE = re.compile(r"level:\s+'(\d+)'", re.IGNORECASE)
_RULE_DESC_RE = re.compile(r"description:\s+'(.+)'", re.IGNORECASE)


def parse_logtest_output(log_line: str, raw_output: str) -> LogtestResult:
    """Parse the raw text output of wazuh-logtest into a LogtestResult."""
    result = LogtestResult(log=log_line, success=False, raw_output=raw_output)

    current_phase: LogtestPhase | None = None

    for line in raw_output.splitlines():
        phase_m = _PHASE_RE.match(line)
        if phase_m:
            if current_phase:
                result.phases.append(current_phase)
            current_phase = LogtestPhase(name=phase_m.group(1).strip())
            continue

        if current_phase:
            field_m = _FIELD_RE.match(line)
            if field_m:
                k, v = field_m.group(1).strip(), field_m.group(2).strip()
                current_phase.fields[k] = v

    if current_phase:
        result.phases.append(current_phase)

    # Extract key summary fields from all phases
    for phase in result.phases:
        if "decoder" in phase.name.lower() or "2" in phase.name:
            if "decoder" in " ".join(phase.fields.keys()).lower():
                for k, v in phase.fields.items():
                    if "name" in k.lower():
                        result.decoder_name = v
        if "rule" in phase.name.lower() or "3" in phase.name:
            for k, v in phase.fields.items():
                kl = k.lower()
                if "id" in kl and not result.rule_id:
                    result.rule_id = v
                elif "level" in kl and not result.rule_level:
                    result.rule_level = v
                elif "description" in kl and not result.rule_description:
                    result.rule_description = v

    # Also scan raw output for quick extracts
    if m := _DECODER_RE.search(raw_output):
        result.decoder_name = result.decoder_name or m.group(1)
    if m := _RULE_ID_RE.search(raw_output):
        result.rule_id = result.rule_id or m.group(1)
    if m := _RULE_LEVEL_RE.search(raw_output):
        result.rule_level = result.rule_level or m.group(1)
    if m := _RULE_DESC_RE.search(raw_output):
        result.rule_description = result.rule_description or m.group(1)

    result.success = len(result.phases) >= 2
    return result


# ---------------------------------------------------------------------------
# SSH runner
# ---------------------------------------------------------------------------

def _build_ssh_cmd(cfg: WazuhSSHConfig) -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if cfg.identity_file:
        cmd += ["-i", cfg.identity_file]
    cmd += ["-p", str(cfg.port)]
    cmd += [f"{cfg.user}@{cfg.host}"]
    cmd += [cfg.logtest_path, "-q"]
    return cmd


def run_logtest_ssh(
    log_samples: list[str],
    cfg: WazuhSSHConfig,
    timeout: int = 30,
) -> list[LogtestResult]:
    """
    Send log_samples to wazuh-logtest on the remote host via SSH.
    Returns one LogtestResult per sample in order.
    """
    if not cfg.is_configured():
        return [
            LogtestResult(log=s, success=False, error="SSH not configured")
            for s in log_samples
        ]

    cmd = _build_ssh_cmd(cfg)
    stdin_text = "\n".join(log_samples) + "\n"

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return [
            LogtestResult(log=s, success=False, error="ssh binary not found in PATH")
            for s in log_samples
        ]
    except subprocess.TimeoutExpired:
        return [
            LogtestResult(log=s, success=False, error="SSH connection timed out")
            for s in log_samples
        ]
    except Exception as exc:
        return [
            LogtestResult(log=s, success=False, error=str(exc))
            for s in log_samples
        ]

    if proc.returncode not in (0, 1):
        err = (proc.stderr or proc.stdout or "SSH failed").strip()
        return [
            LogtestResult(log=s, success=False, error=err)
            for s in log_samples
        ]

    # Split output by "Testing" prompt or separator lines
    raw = proc.stdout
    return _split_and_parse(log_samples, raw)


def _split_and_parse(log_samples: list[str], raw_output: str) -> list[LogtestResult]:
    """
    wazuh-logtest prints results one after another. Split on blank separators
    between phases and match back to input samples.
    """
    # Use double-newline blocks as result boundaries
    blocks = re.split(r"\n{3,}", raw_output.strip())
    results: list[LogtestResult] = []

    for i, sample in enumerate(log_samples):
        block = blocks[i] if i < len(blocks) else ""
        result = parse_logtest_output(sample, block)
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# Run a single sample inline (no SSH) — for local quick-test
# ---------------------------------------------------------------------------

def run_logtest_local(
    log_samples: list[str],
    logtest_path: str = "/var/ossec/bin/wazuh-logtest",
) -> list[LogtestResult]:
    """Try to call local wazuh-logtest (only works on Linux/Wazuh host)."""
    try:
        proc = subprocess.run(
            [logtest_path, "-q"],
            input="\n".join(log_samples) + "\n",
            capture_output=True,
            text=True,
            timeout=20,
        )
        return _split_and_parse(log_samples, proc.stdout)
    except Exception as exc:
        return [
            LogtestResult(log=s, success=False, error=str(exc))
            for s in log_samples
        ]
