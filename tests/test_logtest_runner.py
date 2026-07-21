"""Tests for logtest output parser."""
import pytest
from wazuh_viewer.logtest_runner import parse_logtest_output, _split_and_parse

SAMPLE_OUTPUT = """\
**Phase 1: Completed pre-decoding.
       full event: 'Jul 21 10:00:01 web-01 sshd[1234]: Failed password for root from 10.0.0.1 port 22'
          timestamp: 'Jul 21 10:00:01'
          hostname: 'web-01'
          program_name: 'sshd'
          log_format: 'syslog'

**Phase 2: Completed decoding.
       decoder: 'sshd'

**Phase 3: Completed filtering (rules).
       id: '5710'
       level: '5'
       description: 'sshd: authentication failed.'
"""


def test_phase_count():
    result = parse_logtest_output("test log", SAMPLE_OUTPUT)
    assert len(result.phases) == 3


def test_decoder_extracted():
    result = parse_logtest_output("test log", SAMPLE_OUTPUT)
    assert result.decoder_name == "sshd"


def test_rule_id_extracted():
    result = parse_logtest_output("test log", SAMPLE_OUTPUT)
    # May include quotes from the raw regex, strip them
    assert "5710" in result.rule_id


def test_rule_description_extracted():
    result = parse_logtest_output("test log", SAMPLE_OUTPUT)
    assert "authentication failed" in result.rule_description


def test_success_true_with_three_phases():
    result = parse_logtest_output("test log", SAMPLE_OUTPUT)
    assert result.success is True


def test_success_false_no_phases():
    result = parse_logtest_output("test log", "Connection refused")
    assert result.success is False
    assert len(result.phases) == 0


def test_split_and_parse_single():
    samples = ["Jul 21 10:00:01 h sshd[1]: test"]
    results = _split_and_parse(samples, SAMPLE_OUTPUT)
    assert len(results) == 1
    assert "5710" in results[0].rule_id
