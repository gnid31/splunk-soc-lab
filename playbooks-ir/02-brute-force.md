# IR Playbook 02 — Brute Force Authentication

**Scope**: Repeated failed authentication attempts targeting Windows RDP/SMB or Linux SSH.

**MITRE ATT&CK**: T1110 (Brute Force), T1078 (Valid Accounts if successful), T1021 (Remote Services).

---

## 1. Preparation

- Correlation search `SOCLab - T1110 - Brute Force Authentication` enabled.
- Fail2ban or Windows Account Lockout policy in place as first-line defense.
- On-call has permissions to modify firewall rules and disable accounts.

## 2. Detection & Analysis

**Trigger**: Notable event with `failures >= 10` for a `src_ip` within 5 min.

### 2.1 Triage

| Question | SPL |
|---|---|
| Source IP + failures count | `index=notable mitre_technique="T1110" \| table _time src_ip host failures accounts` |
| Was any attempt SUCCESSFUL? | Windows: `index=wineventlog EventCode=4624 IpAddress=<src_ip>`  <br>Linux: `index=linux_auditd sourcetype=linux:auth "Accepted password" src_ip=<src_ip>` |
| Which accounts targeted? | look at `accounts` field in notable |
| Is source internal or external? | `whois` on src_ip; internal → probably compromised pivot |

### 2.2 If SUCCESSFUL logon occurred

Escalate: it's no longer brute force — it's an active intrusion (T1078). Switch to phishing / lateral-movement playbook and expand scope.

## 3. Containment

External source, no success:

1. Block source IP at edge firewall / VPS UFW:
   ```
   ufw insert 1 deny from <src_ip>
   ```
2. Rate-limit or temporarily disable the targeted authentication service if broad attack.

Internal source, or success confirmed:

1. Isolate source host (network quarantine).
2. Disable the targeted account or force password reset.
3. Invalidate all sessions for that account.

## 4. Eradication

- If internal source compromised: run full incident scope on that host.
- Remove any persistence added by attacker (check Sysmon 13 / scheduled tasks / new users).

## 5. Recovery

- Restore normal firewall rules once brute force stops.
- Monitor targeted account for 48h.
- Enforce MFA on affected accounts.

## 6. Post-Incident

- Fill [`reports/brute-force-report-template.md`](../reports/brute-force-report-template.md).
- Tune `SOCLab - T1110` threshold if false positives seen.
- Consider adding geo-filter to authentication.

## SPL Toolkit

```
# Timeline of failures + successes for a src_ip
index=wineventlog (EventCode=4625 OR EventCode=4624) IpAddress=<src_ip> | timechart span=1m count by EventCode

# Failed users list (potential brute-force target)
index=wineventlog EventCode=4625 IpAddress=<src_ip> | stats count by TargetUserName

# Linux equivalent
index=linux_auditd sourcetype=linux:auth src=<src_ip> | timechart span=1m count by "authentication_result"
```
