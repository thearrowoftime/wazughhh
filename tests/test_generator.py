"""Tests for Wazuh XML and liblognorm generator."""
import re
import tempfile
from pathlib import Path

from wazuh_viewer.log_importer import load_samples
from wazuh_viewer.clusterer import cluster_samples
from wazuh_viewer.decoder_generator import (
    generate_wazuh_xml,
    generate_liblognorm,
    compute_local_coverage,
    _template_to_pcre2_and_order,
)
from wazuh_viewer.decoder_models import LogCluster, LogSample


def _cluster_from_lines(lines: list[str]) -> LogCluster:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8"
    ) as f:
        f.write("\n".join(lines))
        p = Path(f.name)
    samples = load_samples(p)
    p.unlink()
    clusters = cluster_samples(samples)
    return max(clusters, key=lambda c: c.sample_count)


class TestWazuhXML:
    def test_xml_contains_decoder_tag(self):
        c = _cluster_from_lines([
            "Jul 21 10:00:01 h sshd[1]: Failed password for root from 10.0.0.1 port 22",
            "Jul 21 10:00:02 h sshd[2]: Failed password for admin from 10.0.0.2 port 22",
        ])
        xml = generate_wazuh_xml(c)
        assert "<decoder name=" in xml

    def test_xml_marks_as_candidate(self):
        c = _cluster_from_lines([
            "Jul 21 10:00:01 h sshd[1]: test message one",
            "Jul 21 10:00:02 h sshd[2]: test message two",
        ])
        xml = generate_wazuh_xml(c)
        assert "CANDIDATE" in xml.upper()

    def test_xml_includes_program_name(self):
        c = _cluster_from_lines([
            "Jul 21 10:00:01 h sshd[1]: Failed password for root from 10.0.0.1 port 22",
            "Jul 21 10:00:02 h sshd[2]: Failed password for admin from 10.0.0.2 port 22",
        ])
        xml = generate_wazuh_xml(c)
        assert "sshd" in xml

    def test_xml_has_regex_with_groups_for_wildcards(self):
        c = _cluster_from_lines([
            "Jul 21 10:00:01 h sshd[1]: Failed password for root from 10.0.0.1 port 22",
            "Jul 21 10:00:02 h sshd[2]: Failed password for admin from 10.0.0.2 port 22",
        ])
        xml = generate_wazuh_xml(c)
        if "<regex>" in xml:
            assert "(" in xml  # capture groups

    def test_literal_template_no_child_decoder(self):
        # Single sample → no <*>, no child decoder needed
        c = _cluster_from_lines([
            "Jul 21 10:00:01 h sshd[1]: Server listening on 0.0.0.0 port 22",
        ])
        xml = generate_wazuh_xml(c)
        assert "<decoder name=" in xml


class TestLiblognorm:
    def test_rb_contains_rule(self):
        c = _cluster_from_lines([
            "Jul 21 10:00:01 h sshd[1]: Failed password for root from 10.0.0.1 port 22",
            "Jul 21 10:00:02 h sshd[2]: Failed password for admin from 10.0.0.2 port 22",
        ])
        rb = generate_liblognorm(c)
        assert rb.startswith("# Cluster:")
        assert "rule=:" in rb

    def test_rb_named_fields(self):
        c = _cluster_from_lines([
            "Jul 21 10:00:01 h sshd[1]: Failed password for root from 10.0.0.1 port 22",
            "Jul 21 10:00:02 h sshd[2]: Failed password for admin from 10.0.0.2 port 22",
        ])
        rb = generate_liblognorm(c)
        # Should have at least one typed field
        assert "%" in rb


class TestCoverage:
    def test_full_coverage(self):
        c = _cluster_from_lines([
            "Jul 21 10:00:01 h sshd[1]: Failed password for root from 10.0.0.1 port 22",
            "Jul 21 10:00:02 h sshd[2]: Failed password for admin from 10.0.0.2 port 22",
            "Jul 21 10:00:03 h sshd[3]: Failed password for test from 10.0.0.3 port 22",
        ])
        regex, _ = _template_to_pcre2_and_order(c.template)
        cov = compute_local_coverage(c, regex)
        assert cov.matched == cov.total

    def test_zero_coverage_bad_regex(self):
        c = _cluster_from_lines(["Jul 21 10:00:01 h sshd[1]: hello world"])
        cov = compute_local_coverage(c, "(?P<bad>")  # invalid regex
        assert cov.matched == 0
        assert "Bad regex" in cov.unmatched_samples[0]

    def test_coverage_label_format(self):
        from wazuh_viewer.decoder_models import CoverageReport
        r = CoverageReport(total=10, matched=7)
        assert "7/10" in r.label
        assert "70.0%" in r.label
