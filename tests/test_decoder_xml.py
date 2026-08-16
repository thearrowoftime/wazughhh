"""Tests for decoder XML parsing and tree building."""
from wazuh_viewer.decoder_xml import build_decoder_tree, parse_decoder_xml

EXAMPLE = """
<decoder name="example">
  <program_name>^example</program_name>
</decoder>

<decoder name="example">
  <parent>example</parent>
  <regex>User '(\\w+)' logged from '(\\d+.\\d+.\\d+.\\d+)'</regex>
  <order>user, srcip</order>
</decoder>
"""


def test_parses_multiple_rootless_decoder_nodes():
    nodes = parse_decoder_xml(EXAMPLE)
    assert len(nodes) == 2
    assert nodes[0].parent_name is None
    assert nodes[1].parent_name == "example"


def test_tree_attaches_same_name_child_to_parent():
    roots, orphans = build_decoder_tree(parse_decoder_xml(EXAMPLE))
    assert len(roots) == 1
    assert not orphans
    assert len(roots[0].children) == 1
    assert roots[0].children[0].order == ["user", "srcip"]


def test_program_name_defaults_to_osmatch():
    nodes = parse_decoder_xml(EXAMPLE)
    assert nodes[0].program_name.kind == "osmatch"


def test_regex_defaults_to_osregex():
    nodes = parse_decoder_xml(EXAMPLE)
    assert nodes[1].regexes[0].kind == "osregex"


def test_pcre2_type_attribute():
    xml = """
    <decoder name="p">
      <program_name type="pcre2">^app$</program_name>
      <regex type="pcre2">id=(\\d+)</regex>
      <order>id</order>
    </decoder>
    """
    nodes = parse_decoder_xml(xml)
    assert nodes[0].program_name.kind == "pcre2"
    assert nodes[0].regexes[0].kind == "pcre2"


def test_orphan_child_when_parent_missing():
    xml = """
    <decoder name="child">
      <parent>missing-parent</parent>
      <regex>foo (\\w+)</regex>
      <order>user</order>
    </decoder>
    """
    roots, orphans = build_decoder_tree(parse_decoder_xml(xml))
    assert roots == []
    assert len(orphans) == 1
    assert orphans[0].orphan is True


def test_comments_and_candidate_banner_allowed():
    xml = """
    <!-- CANDIDATE — review before deploying -->
    <decoder name="x">
      <prematch>hello</prematch>
    </decoder>
    """
    nodes = parse_decoder_xml(xml)
    assert nodes[0].name == "x"
