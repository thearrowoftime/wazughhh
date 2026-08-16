"""Local wazuh-logtest engine — official Wazuh decoder examples."""
from pathlib import Path

from wazuh_viewer.decoder_xml import build_decoder_tree, parse_decoder_xml
from wazuh_viewer.local_logtest import decode_event, format_logtest, run_logtest

EXAMPLE_XML = """
<decoder name="example">
  <program_name>^example</program_name>
</decoder>

<decoder name="example">
  <parent>example</parent>
  <regex>User '(\\w+)' logged from '(\\d+.\\d+.\\d+.\\d+)'</regex>
  <order>user, srcip</order>
</decoder>
"""

EXAMPLE_LOG = "Jan  1 00:00:00 host example[123]: User 'admin' logged from '192.168.1.1'"

PCRE2_XML = """
<decoder name="example_pcre2">
  <program_name>^example_pcre2$</program_name>
</decoder>

<decoder name="example_pcre2">
  <parent>example_pcre2</parent>
  <regex type="pcre2">User '(.*?)' change email to '(.*?@(.*?))'</regex>
  <order>user, email, domain</order>
</decoder>
"""

JSON_XML = """
<decoder name="raw_json">
  <program_name>nba_program</program_name>
  <prematch>player_information: </prematch>
  <plugin_decoder offset="after_prematch">JSON_Decoder</plugin_decoder>
</decoder>
"""


def test_official_example_extracts_user_and_srcip():
    roots, orphans = build_decoder_tree(parse_decoder_xml(EXAMPLE_XML))
    result = decode_event(EXAMPLE_LOG, roots, orphans)
    assert result.matched
    assert result.decoder_name == "example"
    assert result.fields["user"] == "admin"
    assert result.fields["srcip"] == "192.168.1.1"
    assert result.predecode.program_name == "example"
    assert result.predecode.hostname == "host"


def test_wrong_program_does_not_match():
    roots, orphans = build_decoder_tree(parse_decoder_xml(EXAMPLE_XML))
    log = "Jan  1 00:00:00 host sshd[123]: User 'admin' logged from '192.168.1.1'"
    result = decode_event(log, roots, orphans)
    assert not result.matched
    assert any("program_name" in m.reason for m in result.misses)


def test_pcre2_child_fields():
    roots, orphans = build_decoder_tree(parse_decoder_xml(PCRE2_XML))
    log = "Jan  1 00:00:00 host example_pcre2[1]: User 'foo' change email to 'foo@bar.com'"
    result = decode_event(log, roots, orphans)
    assert result.matched
    assert result.fields["user"] == "foo"
    assert result.fields["email"] == "foo@bar.com"
    assert result.fields["domain"] == "bar.com"


def test_json_plugin_decoder():
    roots, orphans = build_decoder_tree(parse_decoder_xml(JSON_XML))
    log = 'Jan  1 00:00:00 h nba_program: player_information: {"name":"Stephen","surname":"Curry"}'
    result = decode_event(log, roots, orphans)
    assert result.matched
    assert result.fields["name"] == "Stephen"
    assert result.fields["surname"] == "Curry"


def test_plain_log_prematch_decoder():
    xml = """
    <decoder name="plain">
      <prematch>LOGIN SUCCESS</prematch>
      <regex>user=(\\w+) src=(\\d+.\\d+.\\d+.\\d+)</regex>
      <order>user, srcip</order>
    </decoder>
    """
    roots, orphans = build_decoder_tree(parse_decoder_xml(xml))
    result = decode_event("LOGIN SUCCESS user=alice src=10.1.2.3 extra", roots, orphans)
    assert result.matched
    assert result.fields["user"] == "alice"
    assert result.fields["srcip"] == "10.1.2.3"


def test_offset_after_parent():
    xml = """
    <decoder name="app">
      <program_name>^app</program_name>
      <prematch>^prefix </prematch>
    </decoder>
    <decoder name="app-fields">
      <parent>app</parent>
      <regex offset="after_parent">id=(\\d+)</regex>
      <order>id</order>
    </decoder>
    """
    roots, orphans = build_decoder_tree(parse_decoder_xml(xml))
    result = decode_event("Jan  1 00:00:00 h app: prefix id=42 rest", roots, orphans)
    assert result.matched
    assert result.fields["id"] == "42"
    assert result.decoder_name == "app-fields"
    assert result.decoder_parent == "app"


def test_format_looks_like_wazuh_logtest():
    results = run_logtest([EXAMPLE_LOG], xml_text=EXAMPLE_XML)
    text = format_logtest(results[0])
    assert "**Phase 1: Completed pre-decoding." in text
    assert "**Phase 2: Completed decoding." in text
    assert "name: 'example'" in text
    assert "user: 'admin'" in text
    assert "srcip: '192.168.1.1'" in text


def test_no_match_format():
    results = run_logtest(["totally unrelated log line"], xml_text=EXAMPLE_XML)
    text = format_logtest(results[0])
    assert "No decoder matched." in text


def test_cli_sample_decoder_file():
    from wazuh_viewer.local_logtest import main as logtest_main
    xml = Path(__file__).resolve().parent.parent / "data" / "sample_decoders" / "example.xml"
    rc = logtest_main([
        "-d", str(xml),
        "-l", EXAMPLE_LOG,
        "--no-debug",
    ])
    assert rc == 0


def test_orphan_child_still_testable():
    xml = """
    <decoder name="child">
      <parent>missing</parent>
      <regex>User '(\\w+)'</regex>
      <order>user</order>
    </decoder>
    """
    results = run_logtest(["User 'bob' logged in"], xml_text=xml)
    assert results[0].matched
    assert results[0].fields["user"] == "bob"
    assert results[0].warnings
