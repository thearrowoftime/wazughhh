"""Compile Wazuh OS_Regex / OS_Match patterns to Python `re` (or simple matchers).

OS_Regex is NOT PCRE. Notable differences used by real decoder XML:

- `.` is a literal dot; `\\. ` (backslash-dot) matches any character
- `\\w` is ``[A-Za-z0-9\\-@]`` (no underscore)
- `+` / `*` quantify the previous atom
- `()` are capturing groups
- `^` `$` `|` are supported (anchors / alternation), matching Wazuh decoder usage

OS_Match (sregex) is substring / prefix / suffix matching with `|` alternation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# Wazuh OS_Regex character classes (docs: Regular Expression Syntax).
_OSREGEX_CLASS = {
    "w": r"[A-Za-z0-9\-@]",
    "d": r"[0-9]",
    "s": r" ",
    "t": r"\t",
    "p": r"[()*+,\-.:;=?\[\]^_`{|}~#$%&'\"]",
    "W": r"[^A-Za-z0-9\-@]",
    "D": r"[^0-9]",
    "S": r"[^ ]",
}


class PatternError(ValueError):
    """Pattern could not be compiled."""


def osregex_to_python(pattern: str) -> str:
    """Translate an OS_Regex pattern to a Python `re` pattern string."""
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt == ".":
                out.append(".")
            elif nxt in _OSREGEX_CLASS:
                out.append(_OSREGEX_CLASS[nxt])
            else:
                out.append(re.escape(nxt))
            i += 2
            continue
        if ch in "+*":
            out.append(ch)
            i += 1
            continue
        if ch in "()|^$":
            out.append(ch)
            i += 1
            continue
        out.append(re.escape(ch))
        i += 1
    return "".join(out)


def compile_osregex(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(osregex_to_python(pattern))
    except re.error as exc:
        raise PatternError(f"OS_Regex compile failed: {exc}: {pattern!r}") from exc


def compile_pcre2(pattern: str) -> re.Pattern[str]:
    """Approximate PCRE2 with Python `re` (covers typical decoder patterns)."""
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise PatternError(f"PCRE2 compile failed: {exc}: {pattern!r}") from exc


@dataclass(frozen=True)
class OsMatch:
    """Compiled OS_Match (sregex) matcher."""

    raw: str
    alternatives: tuple[tuple[str, bool, bool], ...]  # (text, anchor_start, anchor_end)

    def search(self, text: str) -> re.Match[str] | None:
        """Return a dummy-like match span via `re` so callers can use `.start/.end`."""
        for literal, start_anchored, end_anchored in self.alternatives:
            if start_anchored and end_anchored:
                if text == literal:
                    return re.search(re.escape(literal), text)
            elif start_anchored:
                if text.startswith(literal):
                    return re.match(re.escape(literal), text)
            elif end_anchored:
                if text.endswith(literal):
                    return re.search(re.escape(literal) + r"$", text)
            else:
                pos = text.find(literal)
                if pos >= 0:
                    return re.search(re.escape(literal), text)
        return None


def compile_osmatch(pattern: str) -> OsMatch:
    alts: list[tuple[str, bool, bool]] = []
    for part in pattern.split("|"):
        start = part.startswith("^")
        end = part.endswith("$") and not part.endswith(r"\$")
        body = part[1:] if start else part
        if end and body:
            body = body[:-1]
        alts.append((body, start, end))
    return OsMatch(raw=pattern, alternatives=tuple(alts))


def compile_pattern(pattern: str, kind: str) -> re.Pattern[str] | OsMatch:
    kind = (kind or "osregex").lower()
    if kind in ("osmatch", "sregex"):
        return compile_osmatch(pattern)
    if kind == "pcre2":
        return compile_pcre2(pattern)
    return compile_osregex(pattern)


def search_pattern(compiled: re.Pattern[str] | OsMatch, text: str) -> re.Match[str] | None:
    if isinstance(compiled, OsMatch):
        return compiled.search(text)
    return compiled.search(text)
