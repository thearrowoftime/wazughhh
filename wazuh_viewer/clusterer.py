"""Drain3-based log clustering grouped first by program_name."""
from __future__ import annotations

from collections import defaultdict
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from wazuh_viewer.decoder_models import LogCluster, LogSample


def _make_miner() -> TemplateMiner:
    cfg = TemplateMinerConfig()
    cfg.drain_depth = 4
    cfg.drain_sim_th = 0.4
    cfg.drain_max_children = 100
    cfg.parametrize_numeric_tokens = True
    return TemplateMiner(config=cfg)


def cluster_samples(samples: list[LogSample]) -> list[LogCluster]:
    """
    Group samples by program_name, then run Drain3 on each group.
    Returns a flat list of LogCluster sorted by sample_count descending.
    """
    by_program: dict[str, list[LogSample]] = defaultdict(list)
    for s in samples:
        key = s.program_name or "unknown"
        by_program[key].append(s)

    all_clusters: list[LogCluster] = []
    cluster_id = 0

    for prog, prog_samples in sorted(by_program.items()):
        miner = _make_miner()
        # Map drain cluster_id → list[LogSample]
        drain_map: dict[int, list[LogSample]] = defaultdict(list)
        drain_template: dict[int, str] = {}

        for sample in prog_samples:
            text = sample.message if sample.message else sample.raw
            result = miner.add_log_message(text)
            if result is None:
                continue
            cid = result["cluster_id"]
            drain_map[cid].append(sample)
            drain_template[cid] = result.get("template_mined", text)

        # Refresh templates — they may have been updated by later messages
        for c in miner.drain.clusters:
            if c.cluster_id in drain_template:
                drain_template[c.cluster_id] = c.get_template()

        for drain_cid, csamples in drain_map.items():
            cluster = LogCluster(
                cluster_id=cluster_id,
                template=drain_template.get(drain_cid, ""),
                program_name=prog,
                sample_count=len(csamples),
                samples=csamples,
            )
            all_clusters.append(cluster)
            cluster_id += 1

    all_clusters.sort(key=lambda c: c.sample_count, reverse=True)
    return all_clusters
