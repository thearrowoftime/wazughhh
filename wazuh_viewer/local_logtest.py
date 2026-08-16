"""Local wazuh-logtest: pre-decode + decoder matching without a Wazuh manager.

Mirrors the three-phase CLI output for Phase 1 (syslog header) and Phase 2
(decoder tree). Phase 3 (rules) is not evaluated locally.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from wazuh_viewer.decoder_xml import (
    Decoder,
    DecoderXMLError,
    PatternSpec,
    build_decoder_tree,
    parse_decoder_path,
    parse_decoder_xml,
)
from wazuh_viewer.osregex import search_pattern
from wazuh_viewer.predecoder import parse_syslog_header


@dataclass
class Predecode:
    full_event: str
    timestamp: str
    hostname: str
    program_name: str
    pid: str
    log: str
    log_format: str


@dataclass
class Miss:
    decoder: str
    reason: str


@dataclass
class LocalLogtestResult:
    log: str
    predecode: Predecode
    decoder_name: str = ""
    decoder_parent: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    chain: list[str] = field(default_factory=list)
    misses: list[Miss] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def matched(self) -> bool:
        return bool(self.decoder_name) and not self.error


def predecode_log(raw: str) -> Predecode:
    ts, host, prog, pid, msg, fmt = parse_syslog_header(raw)
    return Predecode(
        full_event=raw,
        timestamp=ts,
        hostname=host,
        program_name=prog,
        pid=pid,
        log=msg,
        log_format=fmt if fmt != "plain" else "",
    )


def _slice(body: str, spec: PatternSpec | None, parent_end: int, prematch_end: int, regex_end: int) -> tuple[str, int]:
    offset = spec.offset if spec is not None else None
    if offset == "after_parent":
        return body[parent_end:], parent_end
    if offset == "after_prematch":
        return body[prematch_end:], prematch_end
    if offset == "after_regex":
        return body[regex_end:], regex_end
    return body, 0


def _match_program(decoder: Decoder, program_name: str) -> bool:
    if decoder.program_name is None:
        return True
    if not program_name:
        return False
    return search_pattern(decoder.program_name.compiled, program_name) is not None


def _extract_regexes(
    decoder: Decoder,
    body: str,
    parent_end: int,
    prematch_end: int,
) -> tuple[dict[str, str], int] | None:
    if not decoder.regexes:
        return {}, prematch_end

    fields: dict[str, str] = {}
    groups: list[str] = []
    regex_end = prematch_end
    for spec in decoder.regexes:
        text, base = _slice(body, spec, parent_end, prematch_end, regex_end)
        m = search_pattern(spec.compiled, text)
        if m is None:
            return None
        groups.extend(g if g is not None else "" for g in m.groups())
        regex_end = base + m.end()

    for name, value in zip(decoder.order, groups):
        fields[name] = value
    return fields, regex_end


def _json_fields(text: str) -> dict[str, str] | None:
    start = text.find("{")
    if start < 0:
        return None
    try:
        obj = json.loads(text[start:])
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    return _flatten_json(obj)


def _flatten_json(obj: object, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for key, val in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(val, (dict, list)):
                out.update(_flatten_json(val, path))
            elif val is None:
                continue
            else:
                out[path] = str(val)
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            path = f"{prefix}.{i}" if prefix else str(i)
            if isinstance(val, (dict, list)):
                out.update(_flatten_json(val, path))
            elif val is None:
                continue
            else:
                out[path] = str(val)
    return out


def _try_decoder(
    decoder: Decoder,
    pre: Predecode,
    body: str,
    parent_end: int,
    is_root: bool,
    misses: list[Miss],
) -> tuple[bool, dict[str, str], int, int] | None:
    """
    Return (matched, fields, new_parent_end, prematch_end) or None if this node
    does not apply. Root nodes that fail are recorded in `misses`.
    """
    if is_root and not _match_program(decoder, pre.program_name):
        if decoder.program_name is not None:
            misses.append(Miss(decoder.name, f"program_name {decoder.program_name.pattern!r} vs {pre.program_name!r}"))
        return None

    prematch_end = parent_end
    if decoder.prematch is not None:
        text, base = _slice(body, decoder.prematch, parent_end, parent_end, parent_end)
        m = search_pattern(decoder.prematch.compiled, text)
        if m is None:
            misses.append(Miss(decoder.name, f"prematch {decoder.prematch.pattern!r} failed"))
            return None
        prematch_end = base + m.end()
    elif is_root and decoder.program_name is None:
        misses.append(Miss(decoder.name, "root decoder has neither program_name nor prematch"))
        return None

    fields: dict[str, str] = {}
    regex_end = prematch_end
    extracted = _extract_regexes(decoder, body, parent_end, prematch_end)
    if extracted is None:
        misses.append(Miss(decoder.name, "regex did not match"))
        return None
    fields, regex_end = extracted

    if decoder.plugin_decoder and "json" in decoder.plugin_decoder.lower():
        dummy = PatternSpec(pattern="", kind="osregex", offset=decoder.plugin_offset)
        text, _ = _slice(body, dummy, parent_end, prematch_end, regex_end)
        js = _json_fields(text)
        if js is None:
            misses.append(Miss(decoder.name, "JSON_Decoder failed"))
            return None
        fields.update(js)

    # Next child's after_parent starts after this node's prematch (or body start).
    next_parent_end = prematch_end if decoder.prematch is not None else parent_end
    return True, fields, next_parent_end, prematch_end


def _walk_children(
    decoder: Decoder,
    pre: Predecode,
    body: str,
    parent_end: int,
    fields: dict[str, str],
    chain: list[str],
    misses: list[Miss],
) -> str:
    """Try all children; accumulate fields. Return last matching decoder name."""
    current_name = decoder.name
    for child in decoder.children:
        result = _try_decoder(child, pre, body, parent_end, is_root=False, misses=misses)
        if result is None:
            continue
        _, child_fields, child_parent_end, _ = result
        fields.update(child_fields)
        chain.append(child.name)
        current_name = child.name
        current_name = _walk_children(child, pre, body, child_parent_end, fields, chain, misses)
    return current_name


def decode_event(raw: str, roots: list[Decoder], orphans: list[Decoder] | None = None) -> LocalLogtestResult:
    pre = predecode_log(raw)
    body = pre.log
    misses: list[Miss] = []
    warnings: list[str] = []

    candidates = list(roots)
    if orphans:
        for orphan in orphans:
            warnings.append(
                f"decoder {orphan.name!r} parent {orphan.parent_name!r} not loaded -- "
                "tested as if the parent already matched"
            )
            candidates.append(orphan)

    for decoder in candidates:
        is_root = not decoder.orphan
        result = _try_decoder(decoder, pre, body, 0, is_root=is_root, misses=misses)
        if result is None:
            continue
        _, fields, parent_end, _ = result
        chain = [decoder.name]
        leaf = _walk_children(decoder, pre, body, parent_end, fields, chain, misses)
        return LocalLogtestResult(
            log=raw,
            predecode=pre,
            decoder_name=leaf,
            decoder_parent=decoder.name,
            fields=fields,
            chain=chain,
            misses=misses,
            warnings=warnings,
        )

    return LocalLogtestResult(
        log=raw,
        predecode=pre,
        misses=misses,
        warnings=warnings,
    )


def format_logtest(result: LocalLogtestResult, debug: bool = True) -> str:
    """Format like `/var/ossec/bin/wazuh-logtest` (Phase 1–2)."""
    p = result.predecode
    lines = [
        "**Phase 1: Completed pre-decoding.",
        f"       full event: '{p.full_event}'",
    ]
    if p.timestamp:
        lines.append(f"       timestamp: '{p.timestamp}'")
    if p.hostname:
        lines.append(f"       hostname: '{p.hostname}'")
    if p.program_name:
        lines.append(f"       program_name: '{p.program_name}'")
    if p.log_format:
        lines.append(f"       log: '{p.log}'")
    else:
        lines.append(f"       log: '{p.log}'")

    lines.append("")
    lines.append("**Phase 2: Completed decoding.")
    if result.error:
        lines.append(f"       ERROR: {result.error}")
    elif result.decoder_name:
        lines.append(f"       name: '{result.decoder_name}'")
        if result.decoder_parent:
            lines.append(f"       parent: '{result.decoder_parent}'")
        for key, value in result.fields.items():
            lines.append(f"       {key}: '{value}'")
    else:
        lines.append("       No decoder matched.")

    lines.append("")
    lines.append("**Phase 3: Completed filtering (rules).")
    lines.append("       No rules loaded (local decoder-only logtest).")

    if result.warnings:
        lines.append("")
        lines.append("-- warnings --")
        for w in result.warnings:
            lines.append(f"  {w}")

    if debug:
        lines.append("")
        lines.append("-- local logtest debug --")
        if result.chain:
            lines.append(f"  chain: {' -> '.join(result.chain)}")
        if result.misses:
            shown = result.misses[:12]
            for miss in shown:
                lines.append(f"  miss {miss.decoder}: {miss.reason}")
            extra = len(result.misses) - len(shown)
            if extra > 0:
                lines.append(f"  … {extra} more misses")
        elif result.decoder_name:
            lines.append("  first matching parent won; children accumulated fields")
        else:
            lines.append("  no parent decoder matched program_name/prematch/regex")

    return "\n".join(lines) + "\n"


def run_logtest(
    logs: list[str],
    xml_text: str | None = None,
    decoder_path: Path | None = None,
    debug: bool = True,
) -> list[LocalLogtestResult]:
    nodes: list[Decoder] = []
    if xml_text and xml_text.strip():
        nodes.extend(parse_decoder_xml(xml_text, source="<editor>"))
    if decoder_path is not None:
        nodes.extend(parse_decoder_path(decoder_path))
    if not nodes:
        raise DecoderXMLError("No decoders loaded — paste XML or load a .xml file")

    roots, orphans = build_decoder_tree(nodes)
    results: list[LocalLogtestResult] = []
    for raw in logs:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        results.append(decode_event(line, roots, orphans))
    return results


def format_many(results: list[LocalLogtestResult], debug: bool = True) -> str:
    blocks = [format_logtest(r, debug=debug) for r in results]
    return "\n".join(blocks)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Local wazuh-logtest — test decoder XML against a log line (no Wazuh manager).",
    )
    parser.add_argument("-d", "--decoder", type=Path, help="Decoder XML file or directory of *.xml")
    parser.add_argument("-x", "--xml", help="Decoder XML string")
    parser.add_argument("-l", "--log", help="Log line (otherwise positional / stdin)")
    parser.add_argument("log_line", nargs="?", help="Log line to test")
    parser.add_argument("--no-debug", action="store_true", help="Hide miss debug section")
    args = parser.parse_args(argv)

    log = args.log or args.log_line
    if log is None and not sys.stdin.isatty():
        log = sys.stdin.read()
    if not log:
        parser.error("provide a log line with -l, as a positional argument, or on stdin")

    lines = [ln for ln in log.splitlines() if ln.strip()]
    try:
        results = run_logtest(
            lines,
            xml_text=args.xml,
            decoder_path=args.decoder,
            debug=not args.no_debug,
        )
    except (DecoderXMLError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(format_many(results, debug=not args.no_debug), end="")
    if results and all(r.matched for r in results):
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
