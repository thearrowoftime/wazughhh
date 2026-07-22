# wazughhh — Wazuh Alert Viewer + Decoder Lab

A terminal TUI (built with [Textual](https://github.com/Textualize/textual)) for SOC analysts and Wazuh engineers.
Two tools in one tab-switched interface:

- **Alert Triage** — filter, deduplicate, inspect and annotate Wazuh alerts; export shift handover reports (Markdown + CSV)
- **Decoder Lab** — import raw rsyslog/syslog files, auto-cluster similar log lines with [Drain3](https://github.com/logpai/Drain3), generate Wazuh XML decoders and liblognorm rulebases, validate against a live Wazuh Manager over SSH, and **batch-deploy all decoders with one click**

---

## Screenshot

```
┌─ Wazuh Alert Viewer ──────────────────────────────────────────────────────────────┐
│ [1] Alerts  [2] Decoder Lab                                                        │
├────────────────┬──────────────────────────────────────────┬────────────────────────┤
│ Filters        │ Count  First seen   Last seen  Lvl  Host │ Group: 5710 @ web-01   │
│ Severity ▼     │   47   2026-07-10   2026-07-10  5  web-01│ HIGH (max level 12)    │
│ Host     ▼     │    3   2026-07-10   2026-07-10 12  db-02 │ Count: 47 events       │
│ MITRE    ▼     │    1   2026-07-10   2026-07-10 15  dc-01 │ First: 2026-07-10 ...  │
│ Status   ▼     │  ...                                      │ MITRE: T1110           │
│ Search [     ] │                                           │                        │
│ Results: 3 grps│                                           │                        │
│ ─── Dedup ─── │                                           │                        │
│ [x] Group rule+│                                           │                        │
│ Window: 60 min │                                           │                        │
│ ─── Export ── │                                           │                        │
│ [Markdown rpt] │                                           │                        │
│ [CSV export  ] │                                           │                        │
└────────────────┴──────────────────────────────────────────┴────────────────────────┘
│ q Quit  1 Alerts  2 Decoder Lab  r Reload  s Save  / Search                        │
└────────────────────────────────────────────────────────────────────────────────────┘
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
| **Alert deduplication** | Checkbox "Group by rule+host" — collapses identical rule+host pairs within a configurable time window (default 60 min) into one row with an event counter; tracks first/last seen and max severity |
| Detail panel | Shows all alert fields + pre-decoder output; group detail shows event count and time range |
| Triage workflow | Set status, assign analyst name, write notes — persisted to JSON |
| **Markdown report** | Exports full shift handover document: status breakdown, severity table, top 10 rules/hosts, escalated alerts with notes, still-investigating section |
| **CSV export** | Exports all filtered alerts as CSV (one row per alert, all triage fields included) — ready for Excel / ticket import |

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
| Single export | Save XML or `.rb` rulebase for the selected cluster to `data/generated/` |
| **Single SSH deploy** | SCP the selected cluster's XML to `/var/ossec/etc/decoders/` on the Wazuh Manager |
| **Batch export** | Export ALL cluster decoders as XML + liblognorm bundles in one click (merged by program_name) |
| **rsyslog .conf generator** | Generate a complete `rsyslog.conf` snippet with `mmnormalize` action blocks + Wazuh JSON forward — one block per program, ready to drop into `/etc/rsyslog.d/` |
| **Deploy ALL + reload** | Batch SCP all XMLs → run `wazuh-logtest --check` → only reload if syntax is clean → `wazuh-control reload` |
| Syntax validation | Runs `wazuh-logtest --check` on the remote host and shows the output before any reload |

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

# With SSH access to Wazuh Manager for live logtest / deploy
python main.py \
  --wazuh-host 10.0.0.5 \
  --wazuh-user root \
  --identity-file ~/.ssh/id_rsa

# Full options
python main.py --help
```

---

## Decoder Lab workflow

### Automate decoders for 80 rsyslog devices

1. Collect raw logs from all devices into one directory (e.g. `data/sample_logs/`)
2. Click **Load directory** — all files are imported and clustered at once
3. The cluster table groups by `program_name` (sshd, sudo, kernel, firewall…) — each row = one pattern
4. Select a cluster — Wazuh XML and liblognorm rulebase appear instantly in the editor
5. Adjust field names or regex if needed — local coverage updates automatically
6. Enter SSH credentials (host, user, key) in the sidebar
7. Click **Export ALL XML + liblognorm** to save everything locally first (review files in `data/generated/`)
8. Click **Generate rsyslog .conf** to produce `wazuh_forward.conf` — one `mmnormalize` action per program
9. Click **Deploy ALL + reload Wazuh** — the tool will:
   - SCP all XML decoders to `/var/ossec/etc/decoders/`
   - Run `wazuh-logtest --check` on the remote host
   - Only call `wazuh-control reload` if syntax is clean
   - Show per-file deploy results in the output panel

> **Note:** all generated decoders are marked as candidates (`<!-- CANDIDATE — review before deploying -->`).  
> Use the logtest output and local coverage to verify before a production deploy.

### Single cluster workflow

1. Enter a log file path and click **Load file**
2. Click a cluster row — inspect Wazuh XML, liblognorm rulebase, predecoder fields, local coverage
3. Edit directly in the TextArea if needed
4. Click **Run logtest (sample)** to test one representative line against the live Wazuh Manager
5. Click **Run logtest (full cluster)** to send up to 50 samples and see match rate
6. Click **Deploy XML via SSH** to push only the selected decoder

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

## Shift report format

The Markdown report (`reports/shift_report_YYYYMMDD_HHMMSS.md`) contains:

- Summary header with analyst name, shift date, total alert count
- Status breakdown table (New / Investigating / Escalated / Resolved / False Positive)
- Severity breakdown (Critical / High / Medium / Low)
- Top 10 triggered rules with description
- Top 10 affected hosts
- Full escalated alert list with analyst notes
- Still-investigating list with assigned analyst and notes

The CSV (`reports/alerts_YYYYMMDD_HHMMSS.csv`) contains one row per alert with all triage metadata.

---

## File formats

### Alert input

| Format | Notes |
|--------|-------|
| Wazuh JSON array | `[{...}, {...}]` |
| Wazuh JSONL | One JSON object per line |
| OpenSearch export | `{"hits":{"hits":[{"_source":{...}}]}}` |
| Wazuh API export | `{"data":{"affected_items":[...]}}` |

### Log input (Decoder Lab)

| Format | Notes |
|--------|-------|
| Plain `.log` / `.txt` | One line = one sample |
| JSONL | Fields: `full_log`, `message`, or `raw_log` |
| JSON list | Array of objects with the above fields |
| Directory | Recursively loads all `.log`, `.txt`, `.jsonl`, `.json` files |

---

## Project structure

```
wazughhh/
├── main.py                        # CLI entry point
├── requirements.txt
├── data/
│   ├── sample_alerts.json         # 10 sample Wazuh alerts
│   ├── sample_logs/               # rsyslog samples (sshd, FortiGate, Cisco IOS, auth, Windows)
│   ├── generated/                 # exported decoders — review here before deploying (git-ignored)
│   └── reports/                   # shift reports — Markdown + CSV (git-ignored)
└── wazuh_viewer/
    ├── app.py                     # Textual TUI — AlertsTab + DecoderLabTab
    ├── models.py                  # Alert, AlertGroup, TriageStatus, SeverityBand, FilterState
    ├── parser.py                  # Alert JSON/JSONL parser
    ├── filters.py                 # Alert filtering + group_alerts() deduplication
    ├── storage.py                 # Triage persistence (JSON)
    ├── reporter.py                # Shift report generator (Markdown + CSV)
    ├── decoder_models.py          # LogSample, LogCluster, LogtestResult, CoverageReport, WazuhSSHConfig
    ├── predecoder.py              # RFC 3164 / RFC 5424 syslog header parser
    ├── log_importer.py            # Multi-format log file importer
    ├── clusterer.py               # Drain3-based log clustering
    ├── decoder_generator.py       # Wazuh XML + liblognorm generator + local coverage
    ├── logtest_runner.py          # SSH wazuh-logtest runner + output parser
    ├── ssh_deployer.py            # SCP deploy + wazuh-logtest --check + wazuh-control reload
    └── rsyslog_generator.py       # rsyslog mmnormalize conf + liblognorm/XML bundle generators
```

---

## Running tests

```bash
python -m pytest tests/ -v
```

**61 tests** covering: predecoder, importer, clusterer, XML/liblognorm generator, local coverage, logtest output parser, alert deduplication/grouping, shift report (Markdown + CSV), rsyslog config and bundle generators.

---

## SSH authentication

All SSH/SCP operations use the system `ssh`/`scp` binaries with key-based authentication:

```bash
# Generate a key pair (if you don't have one)
ssh-keygen -t ed25519 -f ~/.ssh/wazuh_deploy

# Copy the public key to the Wazuh Manager
ssh-copy-id -i ~/.ssh/wazuh_deploy.pub root@10.0.0.5

# Enter the private key path in the Decoder Lab SSH sidebar
# or pass it on startup:
python main.py --identity-file ~/.ssh/wazuh_deploy
```

No passwords are stored. `BatchMode=yes` ensures the tool never hangs waiting for a prompt.

---

## Ideas / future work

**High value:**
- **Live Wazuh Indexer / API source** — pull alerts directly instead of loading files; poll every N seconds
- **Triage history** — append-only log of status changes per alert (who changed what and when)
- **Quick-triage hotkeys** — `i` = Investigating, `f` = False Positive, `e` = Escalate, no mouse needed
- **Watch mode** — monitor a live log file and re-cluster when new lines arrive
- **Wazuh API authentication** — token-based, stored in OS keychain (not plain text)

**Decoder Lab:**
- **Logtest sandbox** — paste any raw log line, send to wazuh-logtest, see all three phases inline
- **Jump to decoder/rule file** — given `decoder.name` from logtest, open the matching XML
- **Decoder conflict checker** — detect when two decoders share `program_name` + overlapping `prematch`
- **Regression test runner** — run all samples against a decoder file, track pass/fail over commits
- **Git-backed decoder versioning** — auto-commit generated files to a local repo so every change is tracked

**Infrastructure:**
- **Multi-agent support** — filter alerts by agent group, OS platform, or custom label
- **RBAC / read-only mode** — restrict triage write operations for junior analysts
