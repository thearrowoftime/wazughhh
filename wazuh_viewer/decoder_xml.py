"""Parse Wazuh decoder XML (files often have multiple root `<decoder>` nodes)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from wazuh_viewer.osregex import PatternError, compile_pattern


class DecoderXMLError(ValueError):
    """Decoder XML could not be parsed."""


@dataclass
class PatternSpec:
    pattern: str
    kind: str  # osregex | osmatch | pcre2
    offset: str | None = None  # after_parent | after_prematch | after_regex
    compiled: object = None


@dataclass
class Decoder:
    name: str
    parent_name: str | None = None
    program_name: PatternSpec | None = None
    prematch: PatternSpec | None = None
    regexes: list[PatternSpec] = field(default_factory=list)
    order: list[str] = field(default_factory=list)
    plugin_decoder: str | None = None
    plugin_offset: str | None = None
    use_own_name: bool = False
    children: list[Decoder] = field(default_factory=list)
    source: str = ""
    orphan: bool = False  # parent referenced but not loaded

    @property
    def is_parent(self) -> bool:
        return self.parent_name is None


def _text(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    return el.text.strip()


def _attr_type(el: ET.Element, default: str) -> str:
    raw = (el.get("type") or default).strip().lower()
    if raw in ("osmatch", "sregex"):
        return "osmatch"
    if raw == "pcre2":
        return "pcre2"
    return "osregex"


def _compile_spec(spec: PatternSpec) -> None:
    spec.compiled = compile_pattern(spec.pattern, spec.kind)


def _parse_decoder_element(el: ET.Element, source: str) -> Decoder:
    name = (el.get("name") or "").strip()
    if not name:
        raise DecoderXMLError(f"decoder without name in {source}")

    parent_el = el.find("parent")
    parent_name = _text(parent_el) or None

    program_spec = None
    program_el = el.find("program_name")
    if program_el is not None and _text(program_el):
        program_spec = PatternSpec(
            pattern=_text(program_el),
            kind=_attr_type(program_el, "osmatch"),
        )
        _compile_spec(program_spec)

    prematch_spec = None
    prematch_el = el.find("prematch")
    if prematch_el is not None and _text(prematch_el):
        prematch_spec = PatternSpec(
            pattern=_text(prematch_el),
            kind=_attr_type(prematch_el, "osregex"),
            offset=(prematch_el.get("offset") or None),
        )
        _compile_spec(prematch_spec)

    regexes: list[PatternSpec] = []
    for regex_el in el.findall("regex"):
        pat = _text(regex_el)
        if not pat:
            continue
        spec = PatternSpec(
            pattern=pat,
            kind=_attr_type(regex_el, "osregex"),
            offset=(regex_el.get("offset") or None),
        )
        _compile_spec(spec)
        regexes.append(spec)

    order: list[str] = []
    order_el = el.find("order")
    if order_el is not None and _text(order_el):
        order = [p.strip() for p in _text(order_el).split(",") if p.strip()]

    plugin_el = el.find("plugin_decoder")
    plugin = _text(plugin_el) or None
    plugin_offset = plugin_el.get("offset") if plugin_el is not None else None

    use_own = _text(el.find("use_own_name")).lower() in ("true", "yes", "1")

    return Decoder(
        name=name,
        parent_name=parent_name,
        program_name=program_spec,
        prematch=prematch_spec,
        regexes=regexes,
        order=order,
        plugin_decoder=plugin,
        plugin_offset=plugin_offset,
        use_own_name=use_own,
        source=source,
    )


_XML_DECL = re.compile(r"<\?xml[^?]*\?>", re.IGNORECASE)


def parse_decoder_xml(xml_text: str, source: str = "<editor>") -> list[Decoder]:
    """Parse one or more `<decoder>` nodes. Files without a single root are wrapped."""
    text = xml_text.strip()
    if not text:
        return []
    text = _XML_DECL.sub("", text, count=1).strip()
    # Allow HTML comments / candidate banners before the first tag
    wrapped = f"<root>{text}</root>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        raise DecoderXMLError(f"Invalid decoder XML ({source}): {exc}") from exc

    nodes: list[Decoder] = []
    for el in root.iter("decoder"):
        try:
            nodes.append(_parse_decoder_element(el, source))
        except PatternError as exc:
            raise DecoderXMLError(f"{source}: decoder {el.get('name')!r}: {exc}") from exc
    return nodes


def parse_decoder_file(path: Path) -> list[Decoder]:
    return parse_decoder_xml(path.read_text(encoding="utf-8", errors="replace"), source=str(path))


def parse_decoder_path(path: Path) -> list[Decoder]:
    """Load a file or every `*.xml` in a directory (non-recursive)."""
    if path.is_dir():
        nodes: list[Decoder] = []
        for xml_file in sorted(path.glob("*.xml")):
            nodes.extend(parse_decoder_file(xml_file))
        return nodes
    return parse_decoder_file(path)


def build_decoder_tree(nodes: list[Decoder]) -> tuple[list[Decoder], list[Decoder]]:
    """
    Attach children to the first root decoder with a matching name.

    Returns (roots, orphans) where orphans are children whose parent was not loaded.
    Orphans are still testable: they are treated as roots with `orphan=True`.
    """
    roots = [d for d in nodes if d.parent_name is None]
    by_root_name: dict[str, Decoder] = {}
    for root in roots:
        by_root_name.setdefault(root.name, root)

    orphans: list[Decoder] = []
    for node in nodes:
        if node.parent_name is None:
            continue
        parent = by_root_name.get(node.parent_name)
        if parent is None:
            # Child of a child (named parent that is not a root), or missing parent.
            # Search any already-attached node with that name, else mark orphan.
            attached = _find_named(roots, node.parent_name)
            if attached is not None:
                attached.children.append(node)
            else:
                node.orphan = True
                orphans.append(node)
        else:
            parent.children.append(node)

    return roots, orphans


def _find_named(nodes: list[Decoder], name: str) -> Decoder | None:
    for node in nodes:
        if node.name == name:
            return node
        found = _find_named(node.children, name)
        if found is not None:
            return found
    return None
