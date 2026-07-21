"""Generate Wazuh XML decoders and liblognorm rulebases from a LogCluster."""
from __future__ import annotations

import re
import xml.dom.minidom as minidom
from dataclasses import dataclass, field
from typing import NamedTuple

from wazuh_viewer.decoder_models import LogCluster, LogSample


# ---------------------------------------------------------------------------
# Named token patterns used for intelligent field naming
# ---------------------------------------------------------------------------

class _TokenRule(NamedTuple):
    name: str              # canonical field name
    pcre2: str             # PCRE2 pattern for Wazuh
    lognorm_type: str      # liblognorm type hint


_TOKEN_RULES: list[_TokenRule] = [
    _TokenRule("srcip",  r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "ipv4"),
    _TokenRule("srcip6", r"[0-9a-fA-F:]{2,39}", "ipv6"),
    _TokenRule("srcport", r"\d{1,5}", "number"),
    _TokenRule("dstport", r"\d{1,5}", "number"),
    _TokenRule("user",   r"\S+", "word"),
    _TokenRule("action", r"(?:accept|deny|drop|allow|reject|block|pass|forward)\w*", "word"),
    _TokenRule("status", r"\d{3}", "number"),
    _TokenRule("url",    r"https?://\S+", "rest"),
    _TokenRule("mac",    r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", "string"),
    _TokenRule("pid",    r"\d+", "number"),
    _TokenRule("id",     r"[0-9a-fA-F\-]{8,}", "string"),
]

_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_PORT_RE = re.compile(r"\b\d{1,5}\b")
_WORD_RE = re.compile(r"\S+")


# ---------------------------------------------------------------------------
# Context-aware name assignment from surrounding literal text
# ---------------------------------------------------------------------------

_CONTEXT_MAP: dict[str, str] = {
    "from": "srcip",
    "src": "srcip",
    "source": "srcip",
    "to": "dstip",
    "dst": "dstip",
    "dest": "dstip",
    "destination": "dstip",
    "port": "srcport",
    "dport": "dstport",
    "sport": "srcport",
    "user": "user",
    "username": "user",
    "account": "user",
    "action": "action",
    "status": "status",
    "pid": "pid",
    "process": "pid",
    "url": "url",
    "uri": "url",
    "mac": "mac",
}


def _infer_name(placeholder_index: int, left_context: str, right_context: str) -> str:
    """Guess a field name from surrounding words in the log template."""
    for fragment in [left_context, right_context]:
        for word in re.findall(r"[a-zA-Z]+", fragment)[::-1]:
            guess = _CONTEXT_MAP.get(word.lower())
            if guess:
                return guess
    return f"field_{placeholder_index}"


def _template_to_pcre2_and_order(
    template: str,
) -> tuple[str, list[str]]:
    """
    Convert a Drain3 template (text with <*> placeholders) to a PCRE2 regex
    and an ordered list of field names.
    """
    parts = template.split("<*>")
    if len(parts) == 1:
        # No wildcards — use literal match
        return re.escape(template), []

    pcre_parts: list[str] = []
    field_names: list[str] = []

    for i, (left, right) in enumerate(zip(parts, parts[1:])):
        escaped_left = re.escape(left)
        pcre_parts.append(escaped_left)

        left_ctx = left[-20:] if len(left) >= 20 else left
        right_ctx = right[:20]
        name = _infer_name(i + 1, left_ctx, right_ctx)
        # Deduplicate names
        if name in field_names:
            name = f"{name}_{i + 1}"
        field_names.append(name)
        pcre_parts.append(r"(\S+)")

    # Append the last literal segment
    pcre_parts.append(re.escape(parts[-1]))

    return "".join(pcre_parts), field_names


def _make_prematch(program_name: str, template: str) -> str:
    """Extract a stable literal prefix from the template for <prematch>."""
    # Take the text before the first <*>
    before_wildcard = template.split("<*>")[0].strip()
    if len(before_wildcard) >= 4:
        # Use up to 60 chars
        return before_wildcard[:60]
    return ""


# ---------------------------------------------------------------------------
# Public generators
# ---------------------------------------------------------------------------

def generate_wazuh_xml(cluster: LogCluster, decoder_name: str | None = None) -> str:
    """
    Generate Wazuh decoder XML for a cluster.
    Returns pretty-printed XML string marked as a candidate (not production-ready).
    """
    prog = cluster.program_name.replace("/", "_").replace(" ", "_") or "custom"
    name = decoder_name or f"decoder_{prog}"
    child_name = f"{name}_fields"

    template = cluster.template
    regex, order = _template_to_pcre2_and_order(template)
    prematch = _make_prematch(cluster.program_name, template)

    lines: list[str] = [
        "<!-- CANDIDATE — review before deploying -->",
        f"<!-- Cluster: {cluster.program_name!r} | samples: {cluster.sample_count} -->",
        f"<!-- Template: {template[:80]} -->",
        "",
        f'<decoder name="{name}">',
    ]

    if cluster.program_name and cluster.program_name not in ("unknown", ""):
        lines.append(f"  <program_name>^{re.escape(cluster.program_name)}</program_name>")

    if prematch and "<*>" not in prematch:
        lines.append(f"  <prematch>{prematch}</prematch>")

    lines.append("</decoder>")
    lines.append("")

    if order:
        lines.append(f'<decoder name="{child_name}">')
        lines.append(f"  <parent>{name}</parent>")
        if prematch and "<*>" not in prematch:
            lines.append(f'  <prematch offset="after_parent">{prematch}</prematch>')
        lines.append(f"  <regex>{regex}</regex>")
        lines.append(f"  <order>{', '.join(order)}</order>")
        lines.append("</decoder>")

    return "\n".join(lines)


def generate_liblognorm(cluster: LogCluster, rule_name: str | None = None) -> str:
    """
    Generate liblognorm rulebase (.rb) for rsyslog mmnormalize.
    Uses simplified type inference from the Drain3 template.
    """
    prog = cluster.program_name or "custom"
    rname = rule_name or f"wazuh_{prog.replace('/', '_')}"
    template = cluster.template
    parts = template.split("<*>")

    if len(parts) == 1:
        # No variables — pure literal rule
        rule_body = template
        return f"# Cluster: {prog!r} n={cluster.sample_count}\nrule=:{rule_body}\n"

    rule_parts: list[str] = []
    field_index = [0]

    for i, (left, right) in enumerate(zip(parts, parts[1:])):
        rule_parts.append(left)
        left_ctx = left[-20:] if len(left) >= 20 else left
        right_ctx = right[:20]
        name = _infer_name(i + 1, left_ctx, right_ctx)
        if f"%{name}:" in " ".join(rule_parts):
            name = f"{name}_{i + 1}"
        # Choose liblognorm type heuristically
        if "ip" in name:
            ltype = "ipv4"
        elif "port" in name or "pid" in name or "status" in name:
            ltype = "number"
        elif "mac" in name:
            ltype = "string"
        else:
            ltype = "word"
        rule_parts.append(f"%{name}:{ltype}%")

    rule_parts.append(parts[-1])
    rule_body = "".join(rule_parts)

    return (
        f"# Cluster: {prog!r} n={cluster.sample_count}\n"
        f"# Template: {template[:80]}\n"
        f"rule=:{rule_body}\n"
    )


# ---------------------------------------------------------------------------
# Local coverage (regex-based, no SSH required)
# ---------------------------------------------------------------------------

from wazuh_viewer.decoder_models import CoverageReport


def compute_local_coverage(cluster: LogCluster, regex_str: str) -> CoverageReport:
    """
    Test `regex_str` against every sample in the cluster's program_name group.
    Returns a CoverageReport.
    """
    try:
        pattern = re.compile(regex_str, re.IGNORECASE)
    except re.error as exc:
        return CoverageReport(
            total=len(cluster.samples),
            matched=0,
            unmatched_samples=[f"Bad regex: {exc}"],
        )

    report = CoverageReport(total=len(cluster.samples))
    for sample in cluster.samples:
        text = sample.message if sample.message else sample.raw
        if pattern.search(text):
            report.matched += 1
        else:
            report.unmatched_samples.append(sample.raw)

    return report
