"""Parse syslog headers the same way Wazuh predecoder does (RFC 3164 & 5424)."""
from __future__ import annotations

import re
from wazuh_viewer.decoder_models import LogSample

# RFC 3164: "Jan  3 12:00:00 host prog[pid]: msg"
_RFC3164 = re.compile(
    r"""^
    (?P<ts>
        (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+
        \d{1,2}\s+\d{2}:\d{2}:\d{2}
    )\s+
    (?P<host>\S+)\s+
    (?:(?P<prog>[A-Za-z0-9_\-\/\.]+?)(?:\[(?P<pid>\d+)\])?:\s+)?
    (?P<msg>.*)$
    """,
    re.VERBOSE | re.DOTALL,
)

# RFC 5424: "<PRI>1 TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG"
_RFC5424 = re.compile(
    r"""^<\d+>1\s+
    (?P<ts>\S+)\s+
    (?P<host>\S+)\s+
    (?P<prog>\S+)\s+
    (?P<pid>\S+)\s+
    \S+\s+        # MSGID
    \S+\s+        # STRUCTURED-DATA
    (?P<msg>.*)$
    """,
    re.VERBOSE | re.DOTALL,
)

# Minimal "<PRI>..." (RFC 3164 with priority)
_RFC3164_PRI = re.compile(
    r"""^<\d+>
    (?P<ts>
        (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+
        \d{1,2}\s+\d{2}:\d{2}:\d{2}
    )\s+
    (?P<host>\S+)\s+
    (?:(?P<prog>[A-Za-z0-9_\-\/\.]+?)(?:\[(?P<pid>\d+)\])?:\s+)?
    (?P<msg>.*)$
    """,
    re.VERBOSE | re.DOTALL,
)


def parse_syslog_header(raw: str) -> tuple[str, str, str, str, str, str]:
    """Return (timestamp, hostname, program_name, pid, message, syslog_format)."""
    for pattern, fmt in [(_RFC5424, "rfc5424"), (_RFC3164_PRI, "rfc3164"), (_RFC3164, "rfc3164")]:
        m = pattern.match(raw.strip())
        if m:
            gd = m.groupdict()
            prog = gd.get("prog") or ""
            pid = gd.get("pid") or ""
            # strip trailing dot from program name if any
            prog = prog.rstrip(":")
            return (
                gd.get("ts", ""),
                gd.get("host", ""),
                prog,
                pid,
                gd.get("msg", raw),
                fmt,
            )
    return "", "", "", "", raw, "plain"


def enrich_sample(sample: LogSample) -> LogSample:
    """Fill in pre-decoder fields from raw log line."""
    ts, host, prog, pid, msg, fmt = parse_syslog_header(sample.raw)
    sample.timestamp = ts
    sample.hostname = host
    sample.program_name = prog
    sample.pid = pid
    sample.message = msg
    sample.syslog_format = fmt
    return sample
