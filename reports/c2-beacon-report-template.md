# Post-Incident Report — C2 Beacon

**Incident ID**: IR-YYYY-NNN
**Severity**: Critical
**Detected**: YYYY-MM-DD HH:MM UTC by Splunk detection `SOCLab - T1071.001`
**Reported by**: [Analyst]
**Report date**: YYYY-MM-DD

## Timeline (UTC)

| Time | Event |
|------|-------|
| T-0 | Beaconing began: `<src_ip>` → `<dst_ip>:443` every 30s |
| T+10m | Splunk correlation search identified pattern (10+ intervals, avg 1200 bytes) |
| T+12m | Notable event fired |
| T+18m | Analyst confirmed `<dst_ip>` malicious via CTI lookup (VT: 15/70 vendors) |
| T+22m | C2 IP blocked at edge; host `<src_host>` isolated |
| T+90m | Beaconing process identified: `%APPDATA%\Roaming\svchost.exe` (masquerade) |
| T+3h | Host reimaged |

## Root Cause

- Initial compromise vector: phishing (correlated with prior detection).
- Persistence: scheduled task `\Microsoft\Windows\<random>` running the masquerade binary.
- Beacon: HTTPS POST to `hxxps://<c2-domain>/api/v1/checkin` every 30 s, no jitter.

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| IP | `<c2_ip>` |
| Domain | `<c2_domain>` |
| SHA256 | `<hash of masquerade binary>` |
| JA3 | `<tls fingerprint>` |
| Path | `%APPDATA%\Roaming\svchost.exe` |
| Task Name | `\Microsoft\Windows\<random>` |

## Indicators of Attack (IOAs)

- Regular-interval outbound connections (< 5% jitter).
- Consistent small payload (~1-2 KB per beacon).
- Process masquerading as `svchost.exe` but running from user AppData.
- Scheduled task launching binary from non-standard location.

## MITRE ATT&CK Mapping

- T1071.001 Web Protocols (C2)
- T1573.001 Encrypted Channel (TLS)
- T1053.005 Scheduled Task (Persistence)
- T1036.005 Match Legitimate Name (Defense Evasion)
- T1041 Exfiltration over C2 (if evidence)

## Impact

- Hosts compromised: 1
- Duration in environment: [X hours/days from first beacon]
- Data exfiltrated: [assessment based on beacon volume + duration]
- Credentials at risk: [any credentials on the host]

## Remediation Actions Taken

1. Blocked C2 IP + domain at DNS + firewall.
2. Host reimaged from clean baseline.
3. All credentials used on the host rotated.
4. Full timeline reconstructed from Sysmon + Zeek.
5. IOCs shared with peer SOCs.

## Recommendations

- Tighten Zeek beacon threshold to catch faster (was 10 min window; try 5).
- Deploy application allowlisting to prevent masquerade binaries.
- Add EDR rule: scheduled task creation from non-System user with executable in AppData.
- Regular threat hunting for JA3 anomalies.

## Lessons Learned

- Detection took 10 minutes from first beacon — because search runs every 10 min.
- Consider real-time streaming detection on `zeek/conn.log`.
- Sysmon EventCode=3 correlation identified the process quickly once we had `<dst_ip>`.
- Ansible + reimage script would cut recovery from 90 min → 30 min.
