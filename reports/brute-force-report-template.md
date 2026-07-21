# Post-Incident Report — Brute Force

**Incident ID**: IR-YYYY-NNN
**Severity**: Medium / High
**Detected**: YYYY-MM-DD HH:MM UTC by Splunk detection `SOCLab - T1110`
**Reported by**: [Analyst]
**Report date**: YYYY-MM-DD

## Timeline (UTC)

| Time | Event |
|------|-------|
| T-0 | First 4625 event from `<src_ip>` targeting `Administrator` |
| T+5m | Threshold reached (10 failures in 5m), notable fired |
| T+8m | Analyst confirmed 45 failures, no successful auth (4624) |
| T+12m | `<src_ip>` blocked at UFW on VPS |
| T+15m | Continued monitoring — no further attempts |

## Root Cause

- Public-facing service (RDP/SSH) exposed on default port.
- No account lockout policy enforced OR lockout evaded by low-and-slow.
- MFA not enforced on the targeted account.

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| IP | `<src_ip>` |
| Accounts targeted | `Administrator`, `root`, `admin` |

## Indicators of Attack (IOAs)

- 10+ failed logons from same source within 5 minutes.
- Multiple usernames tried from same source (spray pattern).
- Attempts from IP with no historical logon success.

## MITRE ATT&CK Mapping

- T1110 Brute Force
- T1110.001 Password Guessing (if verified — repeated single account)
- T1110.003 Password Spraying (if verified — multiple accounts)

## Impact

- Successful compromise: **NO** (confirmed via 4624 search — 0 successes).
- Downtime: 0.
- If SUCCESS had occurred: escalate to full intrusion IR.

## Remediation Actions Taken

1. Blocked `<src_ip>` at firewall.
2. Enforced account lockout: 5 failures = 15 min lockout.
3. Enrolled targeted accounts in MFA.
4. Rotated targeted account passwords proactively.

## Recommendations

- Move remote services behind VPN or bastion.
- Rate-limit at reverse proxy level.
- Add geo-blocking for unexpected countries.
- Enable notable auto-block via SOAR after N unique src_ip attempts within an hour.

## Lessons Learned

- Detection triggered in 5 min — acceptable.
- Manual block took additional 4 min — should be automated.
- Consider auto-triaging brute force from known bad ranges (immediate block without notable).
