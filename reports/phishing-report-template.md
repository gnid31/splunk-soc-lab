# Post-Incident Report — Phishing

**Incident ID**: IR-YYYY-NNN
**Severity**: High / Critical
**Detected**: YYYY-MM-DD HH:MM UTC by Splunk detection `SOCLab - T1059.001`
**Reported by**: [Analyst name]
**Report date**: YYYY-MM-DD

## Timeline (UTC)

| Time | Actor | Event |
|------|-------|-------|
| T-0 | Attacker | Malicious document delivered to `user@example.com` |
| T+2m | User | Opened attachment `invoice.docm` |
| T+2m10s | Endpoint | Sysmon EventCode=1: `powershell.exe -EncodedCommand ...` (ParentImage=`WINWORD.EXE`) |
| T+2m30s | Splunk | Notable event fired |
| T+5m | Analyst | Triage began |
| T+15m | Analyst | Host `win-ep-01` network-isolated via firewall rule |
| T+45m | IT | User password rotated, host reimaged |

## Root Cause

Phishing email bypassed the mail gateway due to [reason: missing DKIM/SPF check, unknown sender allowlisted, etc.]. The user was not trained to recognize [specific lure]. Once the macro executed, PowerShell downloaded a second-stage payload from `hxxps://[C2]/payload.ps1`.

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| SHA256 | `<hash of attachment>` |
| SHA256 | `<hash of dropped binary>` |
| Domain | `<c2-domain>` |
| IP | `<c2-ip>` |
| Registry | `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\<name>` |
| Filename | `%TEMP%\<random>.exe` |

## Indicators of Attack (IOAs)

- Office application (`WINWORD.EXE`) spawning `powershell.exe`.
- PowerShell with `-EncodedCommand` argument.
- Outbound HTTP to unusual IP within 30s of PowerShell exec.
- Registry Run key added by non-installer process.

## MITRE ATT&CK Mapping

| Tactic              | Technique                                |
|---------------------|------------------------------------------|
| Initial Access      | T1566.001 Spearphishing Attachment       |
| Execution           | T1059.001 PowerShell, T1204.002 User Exec|
| Persistence         | T1547.001 Registry Run Key               |
| Command & Control   | T1071.001 Web Protocols                  |

## Impact

- Hosts affected: 1
- Credentials at risk: [account name]
- Data exfil: [confirmed / no evidence]
- Business downtime: [X hours]

## Remediation Actions Taken

1. Host reimaged from clean gold image.
2. User password + MFA re-enrolled.
3. IOCs added to firewall blocklist + EDR.
4. Email sender + hash added to gateway blocklist.
5. User re-trained; targeted phishing simulation queued.

## Recommendations

1. **Preventive**: enforce macro-blocking policy in Office; disable macros from Internet zone.
2. **Detective**: tune `SOCLab - T1059.001` to add exclusion for signed enterprise tooling (reduce FPs).
3. **Responsive**: automate host isolation via SOAR when notable severity=critical.

## Lessons Learned

- Detection worked as designed (< 30 s from execution to notable).
- Mean time to isolate: 15 minutes — target 5 minutes.
- Need pre-approved firewall API access for on-call analyst.
