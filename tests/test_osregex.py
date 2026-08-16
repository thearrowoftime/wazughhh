"""Tests for OS_Regex / OS_Match translation."""
from wazuh_viewer.osregex import (
    compile_osmatch,
    compile_osregex,
    osregex_to_python,
    search_pattern,
)


def test_literal_dot_in_osregex_matches_ip():
    # Wazuh OS_Regex: `.` is a literal dot — this is how IP regexes work.
    pat = compile_osregex(r"(\d+.\d+.\d+.\d+)")
    m = pat.search("from 192.168.1.1 port")
    assert m is not None
    assert m.group(1) == "192.168.1.1"


def test_escaped_dot_is_any_char():
    pat = compile_osregex(r"a\.c")
    assert pat.search("abc")
    assert pat.search("aXc")
    assert not compile_osregex(r"a.c").search("aXc")  # literal dot


def test_word_class_excludes_underscore():
    pat = compile_osregex(r"^(\w+)$")
    assert pat.match("admin-1@host")
    assert not pat.match("has_underscore")


def test_plus_on_digit_class():
    pat = compile_osregex(r"\d+")
    assert pat.search("ab12cd").group(0) == "12"


def test_osmatch_prefix():
    m = compile_osmatch("^sshd")
    assert search_pattern(m, "sshd")
    assert search_pattern(m, "sshd-foo")
    assert search_pattern(m, "foo-sshd") is None


def test_osmatch_alternation():
    m = compile_osmatch("^sendmail|^postfix")
    assert search_pattern(m, "postfix")
    assert search_pattern(m, "sendmail")
    assert search_pattern(m, "sshd") is None


def test_osmatch_substring():
    m = compile_osmatch("auth")
    assert search_pattern(m, "pam_unix(sshd:auth)")


def test_osregex_to_python_parentheses_capture():
    py = osregex_to_python(r"User '(\w+)'")
    assert "(" in py and ")" in py
