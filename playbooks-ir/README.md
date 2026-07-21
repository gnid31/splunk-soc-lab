# Incident Response Playbooks — NIST SP 800-61

Three IR playbooks aligned to NIST SP 800-61 Rev. 2 lifecycle:
**Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity**.

| Playbook                       | Trigger (Splunk Detection)                | MITRE Techniques         |
|--------------------------------|-------------------------------------------|--------------------------|
| [Phishing](01-phishing.md)     | Encoded PowerShell, LSASS access, T1566.001 | T1566.001, T1059.001     |
| [Brute Force](02-brute-force.md)| T1110 detection (10+ failed logons)      | T1110, T1078             |
| [C2 Beacon](03-c2-beacon.md)    | T1071.001 HTTP beaconing                 | T1071.001, T1041         |

Each playbook has a companion **post-incident report template** at [`../reports/`](../reports/).

## Common Execution Flow

```
             +-------------------+
             | Splunk Notable    |
             | Event fires       |
             +---------+---------+
                       |
                       v
             +-------------------+
             | Analyst triage    |
             | via dashboard     |
             +---------+---------+
                       |
                       v
             +-------------------+       +-------------------+
             | Follow playbook   |------>| Fill report       |
             | steps             |       | template          |
             +-------------------+       +-------------------+
```
