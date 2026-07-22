"""
Deploy generated Wazuh decoders to a remote Wazuh Manager via SSH/SCP.

All operations use the system ssh/scp binaries (no shell=True).
No credentials are stored — uses key-based auth only.
"""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from wazuh_viewer.decoder_models import WazuhSSHConfig


REMOTE_DECODER_DIR = "/var/ossec/etc/decoders"
WAZUH_LOGTEST_BIN  = "/var/ossec/bin/wazuh-logtest"


@dataclass
class DeployResult:
    success: bool
    message: str
    stdout: str = ""
    stderr: str = ""


def _base_ssh(cfg: WazuhSSHConfig) -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if cfg.identity_file:
        cmd += ["-i", cfg.identity_file]
    cmd += ["-p", str(cfg.port), f"{cfg.user}@{cfg.host}"]
    return cmd


def _base_scp(cfg: WazuhSSHConfig) -> list[str]:
    cmd = ["scp", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if cfg.identity_file:
        cmd += ["-i", cfg.identity_file]
    cmd += ["-P", str(cfg.port)]
    return cmd


def _run(cmd: list[str], timeout: int = 30) -> DeployResult:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        ok = proc.returncode == 0
        return DeployResult(
            success=ok,
            message="OK" if ok else f"Exit {proc.returncode}",
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
        )
    except FileNotFoundError as e:
        return DeployResult(success=False, message=f"Binary not found: {e}")
    except subprocess.TimeoutExpired:
        return DeployResult(success=False, message="Timed out")
    except Exception as e:
        return DeployResult(success=False, message=str(e))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_connection(cfg: WazuhSSHConfig, timeout: int = 10) -> DeployResult:
    """SSH connectivity test — runs `echo ok` on the remote host."""
    if not cfg.is_configured():
        return DeployResult(success=False, message="SSH host not configured")
    cmd = _base_ssh(cfg) + ["echo", "ok"]
    r = _run(cmd, timeout=timeout)
    if r.success and "ok" in r.stdout:
        return DeployResult(success=True, message="SSH connection OK")
    return r


def validate_decoders(cfg: WazuhSSHConfig, timeout: int = 20) -> DeployResult:
    """
    Run `/var/ossec/bin/wazuh-logtest --check` on the remote host.
    Returns decoder syntax check output.
    """
    logtest = cfg.logtest_path or WAZUH_LOGTEST_BIN
    cmd = _base_ssh(cfg) + [logtest, "--check"]
    r = _run(cmd, timeout=timeout)
    if r.success:
        r.message = "Decoder validation passed"
    return r


def deploy_decoder_xml(
    xml_content: str,
    filename: str,
    cfg: WazuhSSHConfig,
    remote_dir: str = REMOTE_DECODER_DIR,
    timeout: int = 30,
) -> DeployResult:
    """
    Upload *xml_content* to `{remote_dir}/{filename}` on the Wazuh Manager.
    Uses a temp file + scp.
    """
    if not cfg.is_configured():
        return DeployResult(success=False, message="SSH host not configured")

    if not filename.endswith(".xml"):
        filename += ".xml"

    # Write to a local temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(xml_content)
        local_path = tf.name

    remote_path = f"{remote_dir}/{filename}"
    scp_cmd = _base_scp(cfg) + [local_path, f"{cfg.user}@{cfg.host}:{remote_path}"]
    result = _run(scp_cmd, timeout=timeout)

    try:
        Path(local_path).unlink()
    except Exception:
        pass

    if result.success:
        result.message = f"Deployed → {cfg.host}:{remote_path}"
    return result


def deploy_liblognorm_rb(
    rb_content: str,
    filename: str,
    cfg: WazuhSSHConfig,
    remote_dir: str = "/etc/rsyslog.d/liblognorm",
    timeout: int = 30,
) -> DeployResult:
    """Upload liblognorm rulebase to the remote rsyslog host."""
    if not cfg.is_configured():
        return DeployResult(success=False, message="SSH host not configured")

    if not filename.endswith(".rb"):
        filename += ".rb"

    # Ensure remote dir exists
    mkdir_cmd = _base_ssh(cfg) + ["mkdir", "-p", remote_dir]
    _run(mkdir_cmd, timeout=10)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".rb", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(rb_content)
        local_path = tf.name

    remote_path = f"{remote_dir}/{filename}"
    scp_cmd = _base_scp(cfg) + [local_path, f"{cfg.user}@{cfg.host}:{remote_path}"]
    result = _run(scp_cmd, timeout=timeout)

    try:
        Path(local_path).unlink()
    except Exception:
        pass

    if result.success:
        result.message = f"Deployed rulebase → {cfg.host}:{remote_path}"
    return result


def reload_wazuh_manager(cfg: WazuhSSHConfig, timeout: int = 30) -> DeployResult:
    """Reload Wazuh Manager ruleset without full restart (fast, no data loss)."""
    cmd = _base_ssh(cfg) + ["/var/ossec/bin/wazuh-control", "reload"]
    r = _run(cmd, timeout=timeout)
    if r.success:
        r.message = "Wazuh Manager ruleset reloaded"
    return r


def run_logtest_check(cfg: WazuhSSHConfig, timeout: int = 20) -> DeployResult:
    """Run wazuh-logtest --check to validate deployed decoder syntax."""
    logtest = cfg.logtest_path or WAZUH_LOGTEST_BIN
    cmd = _base_ssh(cfg) + [logtest, "--check"]
    r = _run(cmd, timeout=timeout)
    if r.success:
        r.message = f"Syntax OK — {r.stdout[:120] or 'no errors'}"
    else:
        r.message = f"Syntax errors: {r.stderr[:200] or r.stdout[:200]}"
    return r
