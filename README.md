# wazughhh

Wazuh alert triage TUI with Decoder Lab: cluster logs, generate decoders, test them locally or over SSH. Required: Python 3.11+.

```bash
pip install -r requirements.txt
python main.py
python logtest.py -d data/sample_decoders/example.xml -l "Jan  1 00:00:00 host example[123]: User 'admin' logged from '192.168.1.1'"
```

On a Wazuh manager, over SSH:

```bash
python main.py --wazuh-host 10.0.0.5 --wazuh-user root --identity-file ~/.ssh/id_rsa
```
