"""Import raw log lines from .log, .txt, .jsonl and .json files."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from wazuh_viewer.decoder_models import LogSample
from wazuh_viewer.predecoder import enrich_sample


def _samples_from_text(path: Path) -> Iterable[LogSample]:
    text = path.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        yield LogSample(raw=line, source_file=path.name, line_number=i)


def _samples_from_jsonl(path: Path) -> Iterable[LogSample]:
    text = path.read_text(encoding="utf-8", errors="replace")
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        raw = obj.get("full_log") or obj.get("message") or obj.get("raw_log") or str(obj)
        yield LogSample(raw=raw, source_file=path.name, line_number=i)


def _samples_from_json(path: Path) -> Iterable[LogSample]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if isinstance(data, list):
        for i, item in enumerate(data, 1):
            if isinstance(item, str):
                raw = item
            elif isinstance(item, dict):
                raw = (
                    item.get("full_log")
                    or item.get("message")
                    or item.get("raw_log")
                    or json.dumps(item)
                )
            else:
                continue
            yield LogSample(raw=str(raw), source_file=path.name, line_number=i)
    elif isinstance(data, dict):
        hits = (
            data.get("hits", {}).get("hits")
            or data.get("data", {}).get("affected_items")
            or []
        )
        for i, item in enumerate(hits, 1):
            source = item.get("_source", item) if isinstance(item, dict) else item
            if isinstance(source, dict):
                raw = (
                    source.get("full_log")
                    or source.get("message")
                    or json.dumps(source)
                )
            else:
                raw = str(source)
            yield LogSample(raw=str(raw), source_file=path.name, line_number=i)


def load_samples(path: Path) -> list[LogSample]:
    """Load, enrich with predecoder and return all samples from a file."""
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        raw_samples = list(_samples_from_jsonl(path))
    elif suffix == ".json":
        raw_samples = list(_samples_from_json(path))
    else:  # .log, .txt, and anything else
        raw_samples = list(_samples_from_text(path))

    return [enrich_sample(s) for s in raw_samples]


def load_samples_from_dir(directory: Path, max_per_file: int = 2000) -> list[LogSample]:
    """Recursively load samples from a directory (all supported extensions)."""
    extensions = {".log", ".txt", ".jsonl", ".json"}
    samples: list[LogSample] = []
    for p in sorted(directory.rglob("*")):
        if p.suffix.lower() in extensions and p.is_file():
            file_samples = load_samples(p)
            samples.extend(file_samples[:max_per_file])
    return samples
