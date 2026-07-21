"""Tests for Drain3 clustering."""
import tempfile
from pathlib import Path

from wazuh_viewer.log_importer import load_samples
from wazuh_viewer.clusterer import cluster_samples


def _sshd_samples():
    lines = [
        "Jul 21 10:00:01 web sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Jul 21 10:00:02 web sshd[2]: Failed password for admin from 10.0.0.2 port 22 ssh2",
        "Jul 21 10:00:03 web sshd[3]: Failed password for test from 192.168.1.5 port 22 ssh2",
        "Jul 21 10:01:00 web sshd[4]: Accepted publickey for deploy from 10.1.0.1 port 22 ssh2",
        "Jul 21 10:02:00 web sshd[5]: Accepted publickey for backup from 10.2.0.1 port 22 ssh2",
    ]
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8"
    ) as f:
        f.write("\n".join(lines))
        p = Path(f.name)
    samples = load_samples(p)
    p.unlink()
    return samples


def test_groups_by_program():
    samples = _sshd_samples()
    clusters = cluster_samples(samples)
    progs = {c.program_name for c in clusters}
    assert "sshd" in progs


def test_separates_distinct_patterns():
    samples = _sshd_samples()
    clusters = cluster_samples(samples)
    # "Failed password" and "Accepted publickey" should form distinct clusters
    assert len(clusters) >= 2


def test_cluster_counts():
    samples = _sshd_samples()
    clusters = cluster_samples(samples)
    total = sum(c.sample_count for c in clusters)
    assert total == len(samples)


def test_templates_have_placeholders():
    samples = _sshd_samples()
    clusters = cluster_samples(samples)
    # The biggest cluster (Failed password) should have <*> placeholders
    top = max(clusters, key=lambda c: c.sample_count)
    assert "<*>" in top.template or top.sample_count == 1
