"""Tests for log importer."""
import json
import tempfile
from pathlib import Path

from wazuh_viewer.log_importer import load_samples


def _tmp(suffix: str, content: str) -> Path:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        return Path(f.name)


def test_load_plain_log():
    p = _tmp(".log", "Jul 21 10:00:01 host sshd[1]: msg one\nJul 21 10:00:02 host sshd[2]: msg two\n")
    samples = load_samples(p)
    p.unlink()
    assert len(samples) == 2
    assert samples[0].program_name == "sshd"
    assert "msg one" in samples[0].message


def test_load_jsonl():
    lines = [
        json.dumps({"full_log": "Jul 21 10:00:01 h sshd[1]: login failed"}),
        json.dumps({"message": "Jul 21 10:00:02 h sshd[2]: login ok"}),
    ]
    p = _tmp(".jsonl", "\n".join(lines))
    samples = load_samples(p)
    p.unlink()
    assert len(samples) == 2
    assert samples[0].program_name == "sshd"


def test_load_json_list():
    data = [
        {"full_log": "Jul 21 10:00:01 h sshd[1]: test"},
        {"full_log": "Jul 21 10:00:02 h kernel: oops"},
    ]
    p = _tmp(".json", json.dumps(data))
    samples = load_samples(p)
    p.unlink()
    assert len(samples) == 2
    progs = {s.program_name for s in samples}
    assert "sshd" in progs
    assert "kernel" in progs


def test_skips_empty_lines():
    p = _tmp(".log", "\n\n  \nJul 21 10:00:01 host prog[1]: hello\n\n")
    samples = load_samples(p)
    p.unlink()
    assert len(samples) == 1


def test_sample_logs_directory():
    """Ensure bundled sample_logs directory loads without errors."""
    sample_dir = Path(__file__).parent.parent / "data" / "sample_logs"
    if not sample_dir.exists():
        return  # skip if samples not present
    from wazuh_viewer.log_importer import load_samples_from_dir
    samples = load_samples_from_dir(sample_dir)
    assert len(samples) > 0
