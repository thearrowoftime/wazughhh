"""Tests for syslog predecoder."""
import pytest
from wazuh_viewer.predecoder import parse_syslog_header


@pytest.mark.parametrize("raw,expected_prog,expected_host,expected_fmt", [
    (
        "Jul 21 10:00:01 web-01 sshd[1234]: Failed password for root",
        "sshd", "web-01", "rfc3164",
    ),
    (
        # Cisco IOS: the %FACILITY mnemonic is in the message body, not the program field
        "Jul  3 10:00:01 router-01 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success",
        "", "router-01", "rfc3164",
    ),
    (
        "<34>1 2026-07-21T10:00:01Z host1 myapp 12345 - - message body here",
        "myapp", "host1", "rfc5424",
    ),
    (
        "<38>Jul 21 10:00:01 fw-01 kernel: Denied IN=eth0 OUT= SRC=10.0.0.1 DST=8.8.8.8",
        "kernel", "fw-01", "rfc3164",
    ),
    (
        "plain log with no header at all",
        "", "", "plain",
    ),
])
def test_parse_syslog_header(raw, expected_prog, expected_host, expected_fmt):
    ts, host, prog, pid, msg, fmt = parse_syslog_header(raw)
    assert prog == expected_prog, f"prog={prog!r} expected={expected_prog!r}"
    assert host == expected_host
    assert fmt == expected_fmt


def test_pid_extracted():
    _, _, _, pid, _, _ = parse_syslog_header(
        "Jul 21 10:00:01 srv sshd[9999]: some message"
    )
    assert pid == "9999"


def test_message_body():
    _, _, _, _, msg, _ = parse_syslog_header(
        "Jul 21 10:00:01 srv sshd[1]: Failed password for root from 10.0.0.1"
    )
    assert "Failed password" in msg
