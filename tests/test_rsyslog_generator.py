"""Tests for rsyslog config and bundle generators."""
import tempfile
from pathlib import Path

from wazuh_viewer.log_importer import load_samples
from wazuh_viewer.clusterer import cluster_samples
from wazuh_viewer.rsyslog_generator import (
    generate_rsyslog_conf,
    generate_liblognorm_bundle,
    generate_wazuh_xml_bundle,
)


def _clusters_from_lines(lines: list[str]):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as f:
        f.write("\n".join(lines))
        p = Path(f.name)
    samples = load_samples(p)
    p.unlink()
    return cluster_samples(samples)


SSH_LINES = [
    "Jul 21 10:00:01 web sshd[1]: Failed password for root from 10.0.0.1 port 22",
    "Jul 21 10:00:02 web sshd[2]: Failed password for admin from 10.0.0.2 port 22",
    "Jul 21 10:01:00 web sshd[3]: Accepted publickey for deploy from 10.1.0.1 port 22",
]

SUDO_LINES = [
    "Jul 21 10:00:01 db sudo: root : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
    "Jul 21 10:00:02 db sudo: admin : TTY=pts/1 ; USER=root ; COMMAND=/bin/cat",
]


class TestRsyslogConf:
    def test_conf_contains_mmnormalize(self):
        clusters = _clusters_from_lines(SSH_LINES)
        conf = generate_rsyslog_conf(clusters)
        assert "mmnormalize" in conf

    def test_conf_contains_program_name(self):
        clusters = _clusters_from_lines(SSH_LINES)
        conf = generate_rsyslog_conf(clusters)
        assert "sshd" in conf

    def test_conf_contains_wazuh_host(self):
        clusters = _clusters_from_lines(SSH_LINES)
        conf = generate_rsyslog_conf(clusters, wazuh_host="10.0.0.5", wazuh_port=1514)
        assert "10.0.0.5" in conf
        assert "1514" in conf

    def test_conf_marked_as_candidate(self):
        clusters = _clusters_from_lines(SSH_LINES)
        conf = generate_rsyslog_conf(clusters)
        assert "REVIEW BEFORE DEPLOYING" in conf or "auto-generated" in conf

    def test_multiple_programs(self):
        clusters = _clusters_from_lines(SSH_LINES) + _clusters_from_lines(SUDO_LINES)
        conf = generate_rsyslog_conf(clusters)
        assert "sshd" in conf
        assert "sudo" in conf


class TestBundleGenerators:
    def test_xml_bundle_keys_are_program_names(self):
        clusters = _clusters_from_lines(SSH_LINES)
        bundle = generate_wazuh_xml_bundle(clusters)
        assert "sshd" in bundle

    def test_xml_bundle_content_has_decoder_tag(self):
        clusters = _clusters_from_lines(SSH_LINES)
        bundle = generate_wazuh_xml_bundle(clusters)
        for prog, xml in bundle.items():
            assert "<decoder name=" in xml

    def test_rb_bundle_keys_are_program_names(self):
        clusters = _clusters_from_lines(SSH_LINES)
        bundle = generate_liblognorm_bundle(clusters)
        assert "sshd" in bundle

    def test_rb_bundle_has_rules(self):
        clusters = _clusters_from_lines(SSH_LINES)
        bundle = generate_liblognorm_bundle(clusters)
        for prog, rb in bundle.items():
            assert "rule=:" in rb

    def test_multi_cluster_same_program_merged(self):
        clusters = _clusters_from_lines(SSH_LINES)
        bundle = generate_wazuh_xml_bundle(clusters)
        # sshd has 2 clusters (Failed + Accepted) — should be in one file
        assert "sshd" in bundle
        assert bundle["sshd"].count("<decoder name=") >= 2
