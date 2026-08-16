#!/usr/bin/env python3
"""CLI: local wazuh-logtest without a Wazuh manager.

Examples:
  python logtest.py -d data/sample_decoders/example.xml -l "Jan  1 00:00:00 host example[1]: User 'admin' logged from '192.168.1.1'"
  python logtest.py -d decoder.xml < logs.txt
"""
from wazuh_viewer.local_logtest import main

if __name__ == "__main__":
    raise SystemExit(main())
