# Splunk SOC Detection & Incident Response Lab

Splunk Enterprise-based SOC lab across Windows and Linux endpoints. Ingests 5 data
sources via Splunk Universal Forwarder: Windows Event Logs, Sysmon, Linux auditd,
Suricata IDS alerts, and Zeek network logs.

## Architecture

```
                    +-------------------------------+
                    |   VPS 43.228.215.234          |
                    |   Splunk Enterprise           |
                    |   - Indexer + Search Head     |
                    |   - Receiver :9997            |
                    |   - Web UI :8000              |
                    +---------------^---------------+
                                    | forwarding 9997
                    +---------------+---------------+
                    |                               |
        +-----------+-----------+       +-----------+-----------+
        | Ubuntu 192.168.154.166|       | Windows 192.168.154.164|
        | - Splunk UF           |       | - Splunk UF           |
        | - auditd              |       | - Sysmon (Olaf cfg)   |
        | - Suricata IDS        |       | - WinEventLog         |
        | - Zeek                |       |                       |
        +-----------------------+       +-----------------------+
```

## Coverage

- **5 data sources**: Windows Event Logs, Sysmon, Linux auditd, Suricata, Zeek
- **10 SPL correlation searches** mapped to **12 MITRE ATT&CK techniques**
- **10 Atomic Red Team tests** for detection validation
- **3 NIST SP 800-61 IR playbooks**: phishing, brute-force, C2 beacon

## MITRE ATT&CK Coverage

| Tactic              | Techniques                                 |
|---------------------|--------------------------------------------|
| Initial Access      | T1566.001 (Spearphishing Attachment)       |
| Execution           | T1059.001 (PowerShell), T1059.003 (cmd)    |
| Persistence         | T1547.001 (Run Keys), T1053.005 (Sched Task)|
| Privilege Escalation| T1055 (Process Injection)                  |
| Defense Evasion     | T1070.004 (File Deletion)                  |
| Credential Access   | T1003.001 (LSASS Memory), T1110 (Brute Force)|
| Discovery           | T1087 (Account Discovery)                  |
| Lateral Movement    | T1021.002 (SMB/Admin Shares), T1021.001 (RDP)|
| Command & Control   | T1071.001 (Web Protocols)                  |

## Repo Structure

```
ansible/         # Playbooks + inventory to deploy everything
splunk/          # Apps, indexes, inputs.conf, savedsearches
detections/      # 10 SPL correlation search sources
dashboards/      # Analyst triage dashboard XML
atomic-tests/    # Adversary emulation scenarios + expected detections
playbooks-ir/    # 3 NIST 800-61 IR playbooks
docs/            # Setup guide (GUI + CLI)
reports/         # Post-incident report templates
scripts/         # Helpers
```

## Quickstart

See [docs/00-setup.md](docs/00-setup.md).

```bash
cd ansible
ansible-playbook -i inventory/hosts.ini playbooks/site.yml
```

## Timeline

- **March 2026 – May 2026** — Design, deploy, tune detections, IR playbook authoring.

---
Author: nam@cycloneinstruments.ai
