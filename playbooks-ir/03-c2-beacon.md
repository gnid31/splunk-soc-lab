# IR Playbook 03 — Command & Control Beacon

**Scope**: An infected host is sending regular, low-volume outbound traffic — beaconing to a C2 server.

**MITRE ATT&CK**: T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel), T1573 (Encrypted Channel).

---

## 1. Preparation

- Zeek (or Suricata) running on the LAN sensor, `conn.log` shipped to Splunk `zeek` index.
- Correlation search `SOCLab - T1071.001 - HTTP Beaconing` firing every 10 min.
- Passive DNS / threat intel feed (e.g. AbuseIPDB, VirusTotal) available for enrichment.

## 2. Detection & Analysis

**Trigger**: Notable event with sustained low-payload beaconing pattern (10+ intervals, avg_bytes < 2000).

### 2.1 Triage

| Question | SPL |
|---|---|
| Source host + destination IP | `index=notable mitre_technique="T1071.001+T1566.001" \| table _time src_ip dst_ip dst_port intervals avg_bytes` |
| Is destination known-malicious? | check dst_ip against AbuseIPDB / VirusTotal / your CTI feed |
| Regularity of beacon | `index=zeek source=*conn.log src_ip=<src> dst_ip=<dst> \| bin _time span=30s \| stats count by _time` |
| Which process on host? | `index=sysmon EventCode=3 host=<host> DestinationIp=<dst_ip>` |
| SSL/TLS or plain HTTP? | `index=zeek source=*ssl.log dst_ip=<dst>` — inspect JA3/SNI |

### 2.2 Broader Scope

- Check whether same host reached out to other suspicious IPs in the same time window.
- Correlate with any recent PowerShell / LOLbin activity on that host.
- Search all endpoints for connections to the identified C2 IP.

## 3. Containment

1. **Blackhole the C2 IP** at edge firewall / DNS sinkhole:
   ```
   iptables -I OUTPUT -d <c2_ip> -j DROP
   # or add to DNS RPZ
   ```
2. **Isolate source host** if evidence of active data exfil (traffic size or exfil.log entries).
3. Preserve full `conn.log` + `ssl.log` + `dns.log` for the offending host.

## 4. Eradication

1. On the host: identify beaconing process from Sysmon EventCode=3 correlation.
2. Kill the process, remove its binary + persistence.
3. Reset any credentials that may have been exfiltrated.

## 5. Recovery

- Reimage the host if malware persistence not fully understood.
- Monitor for repeat beaconing (attacker may have failover C2).
- Add IOCs (IP, JA3, domain) to blocklists.

## 6. Post-Incident

- Fill [`reports/c2-beacon-report-template.md`](../reports/c2-beacon-report-template.md).
- Share IOCs with peer SOCs / MISP / community.
- Tune beacon detection thresholds if false positive on legitimate periodic traffic (updates, telemetry).

## SPL Toolkit

```
# Full conn history to C2 IP
index=zeek source=*conn.log dst_ip=<dst> | stats count, sum(orig_bytes) as bytes_out, sum(resp_bytes) as bytes_in

# JA3 fingerprint of TLS beacon
index=zeek source=*ssl.log dst_ip=<dst> | stats count by ja3, ja3s, subject

# Endpoints reaching same destination
index=zeek source=*conn.log dst_ip=<dst> | stats count by src_ip
```
