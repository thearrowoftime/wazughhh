# wazughhh — Wazuh Alert Viewer + Decoder Lab

A terminal TUI (built with [Textual](https://github.com/Textualize/textual)) for SOC analysts and Wazuh engineers.
Two tools in one:

- **Alert Triage** — filter, inspect and annotate Wazuh alerts from exported JSON/JSONL files
- **Decoder Lab** — import raw rsyslog/syslog files, auto-cluster similar log lines with [Drain3](https://github.com/logpai/Drain3), generate Wazuh XML decoders and liblognorm rulebases, measure local coverage, and validate against a live Wazuh Manager over SSH

---

## Screenshot

```
┌─ Wazuh Alert Viewer ─────────────────────────────────────────────────┐
│ [1] Alerts  [2] Decoder Lab                                          │
├──────────────┬───────────────────────────────┬───────────────────────┤
│ Filters      │ Time         Lvl  Host  Rule  │ Alert a1b2c3d4        │
│ Severity ▼   │ 2026-07-10   15   dc-01 92213 │ Severity 15 CRITICAL  │
│ Host     ▼   │ 2026-07-10   14   db-02 23504 │ Host: dc-win-01       │
│ MITRE    ▼   │ 2026-07-10   13   fs-03 87802 │ Rule: 92213           │
│ Status   ▼   │ ...                           │ MITRE: T1059.001      │
│ Search [   ] │                               │ Triage status ▼       │
│ Results: 7/10│                               │ Analyst [          ]  │
│              │                               │ Notes                 │
│              │                               │ [                   ] │
└──────────────┴───────────────────────────────┴───────────────────────┘
│ q Quit  1 Alerts  2 Decoder Lab  r Reload  s Save  / Search          │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Features

### Alert Triage tab (`1`)

| Feature | Details |
|---------|---------|
| Filter by severity | Low (0–6), Medium (7–11), High (12–14), Critical (15+) |
| Filter by host | Dropdown populated from loaded alerts |
| Filter by MITRE | IDs, tactics and techniques |
| Filter by triage status | New, Investigating, Escalated, Resolved, False Positive |
| Full-text search | Searches description, rule ID, host, MITRE tags, analyst notes |
| Detail panel | Shows all alert fields + pre-decoder output from the raw alert |
| Triage workflow | Set status, assign analyst name, write notes — persisted to JSON |

### Decoder Lab tab (`2`)

| Feature | Details |
|---------|---------|
| Import logs | `.log`, `.txt`, `.jsonl`, `.json`, whole directories |
| Pre-decoder | Parses RFC 3164 / RFC 5424 syslog headers (timestamp, host, program, PID, message) |
| Clustering | Groups by `program_name`, then Drain3 per group — shows template + sample count |
| Wazuh XML generator | Produces parent + child decoder with `<program_name>`, `<prematch>`, PCRE2 `<regex>` and `<order>` |
| liblognorm generator | Produces rsyslog `mmnormalize` rulebase with typed field placeholders |
| Smart field naming | Infers `srcip`, `dstip`, `srcport`, `user`, `action`, `pid`, `url`, `mac` from context |
| Local coverage | Tests generated regex against all cluster samples — shows `matched/total (%)` |
| wazuh-logtest via SSH | Sends samples to `/var/ossec/bin/wazuh-logtest` on Wazuh Manager, parses Phase 1/2/3 output |
| Export | Saves XML and `.rb` rulebase to `data/generated/` — never deploys automatically |

---

## Installation

```bash
git clone https://github.com/thearrowoftime/wazughhh.git
cd wazughhh
pip install -r requirements.txt
```

**Requirements:** Python 3.11+, `textual`, `drain3`, `httpx`

---

## Usage

```bash
# Default — loads bundled sample alerts
python main.py

# Custom alerts file
python main.py -a /path/to/alerts.json

# With SSH access to Wazuh Manager for live logtest
python main.py \
  --wazuh-host 10.0.0.5 \
  --wazuh-user root \
  --identity-file ~/.ssh/id_rsa

# Full options
python main.py --help
```

### Decoder Lab workflow

1. Enter a log file path (e.g. `data/sample_logs/sshd.log`) and click **Load file**
2. The cluster table shows all discovered patterns sorted by frequency
3. Click a row — the right panel shows Wazuh XML, liblognorm rulebase, pre-decoder fields and local coverage
4. Edit the generated XML/rulebase directly in the editor
5. Enter SSH credentials → **Run logtest (sample)** to validate against a live Wazuh Manager
6. Click **Export XML** or **Export liblognorm** to save to `data/generated/`

> **Important:** generated decoders are candidates and must be reviewed before deploying to `/var/ossec/etc/decoders/`.

---

## Keyboard shortcuts

| Key | Action |
|-----|--------|
| `1` | Switch to Alerts tab |
| `2` | Switch to Decoder Lab tab |
| `r` | Reload alerts + triage state |
| `s` | Save triage (analyst + notes + status) |
| `/` | Focus search box |
| `Esc` | Clear alert selection |
| `q` | Quit |

---

## File formats

The alert loader accepts:

| Format | Notes |
|--------|-------|
| Wazuh JSON array | `[{...}, {...}]` |
| Wazuh JSONL | One JSON object per line |
| OpenSearch export | `{"hits":{"hits":[{"_source":{...}}]}}` |
| Wazuh API export | `{"data":{"affected_items":[...]}}` |

The Decoder Lab importer additionally reads plain `.log` / `.txt` files (one line = one sample) and JSONL with `full_log`, `message` or `raw_log` fields.

---

## Project structure

```
wazughhh/
├── main.py                        # CLI entry point
├── requirements.txt
├── data/
│   ├── sample_alerts.json         # 10 sample Wazuh alerts
│   ├── sample_logs/               # rsyslog samples (sshd, FortiGate, Cisco IOS, Linux auth, Windows)
│   └── generated/                 # exported decoders (git-ignored)
└── wazuh_viewer/
    ├── app.py                     # Textual TUI — two-tab layout
    ├── models.py                  # Alert, TriageStatus, SeverityBand, FilterState
    ├── parser.py                  # Alert JSON/JSONL parser
    ├── filters.py                 # Alert filtering logic
    ├── storage.py                 # Triage persistence (JSON)
    ├── decoder_models.py          # LogSample, LogCluster, LogtestResult, CoverageReport
    ├── predecoder.py              # RFC 3164 / RFC 5424 syslog header parser
    ├── log_importer.py            # Multi-format log file importer
    ├── clusterer.py               # Drain3-based log clustering
    ├── decoder_generator.py       # Wazuh XML + liblognorm generator + local coverage
    └── logtest_runner.py          # SSH wazuh-logtest runner + output parser
```

---

## Running tests

```bash
python -m pytest tests/ -v
```

33 tests covering: predecoder, importer, clusterer, XML/liblognorm generator, coverage, logtest output parser.

---

## What else could be added

See [Ideas](#ideas) below.

---

## Ideas

The tool is deliberately minimal — it doesn't auto-deploy anything. Possible extensions:

**High value:**
- **Live Wazuh Indexer / API source** — pull alerts directly instead of loading files; poll every N seconds
- **Alert deduplication / grouping** — collapse same rule+host within a time window; show event count instead of individual rows
- **Triage history** — append-only log of status changes per alert (who changed what and when)
- **Quick-triage hotkeys** — `i` = Investigating, `f` = False Positive, `e` = Escalate, no mouse needed
- **Shift report export** — Markdown or CSV summary of all triaged alerts in a session

**Decoder Lab:**
- **Logtest sandbox tab** — paste any raw log line, send to wazuh-logtest, see all three phases
- **Jump to decoder/rule file** — given `decoder.name` from logtest, open the matching XML in the editor panel
- **Decoder conflict checker** — detect when two decoders share `program_name` + overlapping `prematch`
- **Regression test runner** — run all samples against a decoder file and show which pass/fail over time
- **rsyslog config generator** — produce the `mmnormalize` `action()` block alongside the `.rb` rulebase

**Infrastructure:**
- **Git-backed decoder versioning** — auto-commit generated files so changes are tracked
- **Wazuh API authentication** — token-based, stored in OS keychain (not plain text)
- **Multi-agent support** — filter alerts by agent group, OS platform, or custom label
