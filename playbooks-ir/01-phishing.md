# IR Playbook 01 — Phishing Attachment Detonation

**Scope**: A user opens a malicious document that spawns encoded PowerShell / stages a payload.

**MITRE ATT&CK**: T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1204.002 (User Execution).

**NIST SP 800-61 Phase Mapping**: Detection & Analysis → Containment → Eradication → Recovery → Post-Incident.

---

## 1. Preparation

- Splunk correlation search `SOCLab - T1059.001 - PowerShell Encoded Command` enabled and firing to notable index.
- Windows endpoints have Sysmon (Olaf modular config) installed, forwarding to Splunk.
- Analyst has read access to `wineventlog` and `sysmon` indexes.
- Contact list ready: user manager, IT operations, on-call engineer.

## 2. Detection & Analysis

**Trigger**: Notable event with `mitre_technique="T1059.001"`.

### 2.1 Initial Triage (5 min)

| Question | SPL / Action |
|---|---|
| Which host? | `index=notable mitre_technique="T1059.001" \| table _time host User CommandLine ParentImage` |
| Parent process (delivery vector)? | Look at `ParentImage` — Outlook, browser, Office = likely phishing |
| Was the encoded command decoded? | Base64 decode `-EncodedCommand` argument: `echo <b64> \| base64 -d \| iconv -f UTF-16LE -t UTF-8` |
| Any child processes? | `index=sysmon EventCode=1 ParentProcessId=<pid> host=<host>` |

### 2.2 Broader Scope

- Check same host for `EventCode=3` (network connections) after PowerShell launch — potential C2.
- Search for the decoded command's IOCs (URLs, IPs) across all endpoints.
- Search email logs (if integrated) for delivery source.

## 3. Containment

Immediate (< 15 min):

1. **Network isolate** the host:
   ```
   # Windows Defender Firewall (via Ansible or RMM)
   New-NetFirewallRule -Name IR-Isolate -Direction Outbound -Action Block -Enabled True
   ```
2. **Disable user's cached credential**: force logout, revoke SSO session.
3. **Preserve evidence**: capture `Sysmon` events for the last 24h.

## 4. Eradication

1. Kill malicious process tree.
2. Remove persistence: check `SOCLab - T1547.001` and `SOCLab - T1053.005` runs for the host.
3. Quarantine downloaded artifacts (path from `FileCreate` Sysmon events).
4. Reset user password.

## 5. Recovery

1. Reimage endpoint if credentials likely dumped (LSASS accessed → yes).
2. Restore data from backup (< 24h before compromise).
3. Re-enable network, monitor for 48h.

## 6. Post-Incident Activity

- Fill [`reports/phishing-report-template.md`](../reports/phishing-report-template.md).
- Update phishing detection rules based on IOAs learned.
- Add sender / hash to email gateway blocklist.
- Communicate lessons to the user (targeted training).

---

## Automation Hooks

- Splunk alert can trigger a webhook to SOAR / this playbook.
- Ansible playbook to isolate host: `ansible-playbook playbooks/ir-isolate.yml -e target_host=<host>` (future work).

## SPL Query Toolkit

```
# All activity from the offending user in last hour
index=* user=<username> earliest=-1h | timechart span=1m count by sourcetype

# All child processes of the initial PowerShell
index=sysmon EventCode=1 host=<host> ParentImage=*powershell.exe | table _time Image CommandLine

# Network egress correlation
index=sysmon EventCode=3 host=<host> earliest=<t-of-encoded-ps>
```
