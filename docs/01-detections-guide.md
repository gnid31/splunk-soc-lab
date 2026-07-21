# Detection Rules Guide — 10 SPL Correlation Searches

Mỗi rule ở dạng savedsearch trong app `soclab_detections`. Xem file gốc: [`splunk/apps/soclab_detections/default/savedsearches.conf`](../splunk/apps/soclab_detections/default/savedsearches.conf).

## Xem danh sách rules

### GUI (Splunk Web)
1. Login `http://43.228.215.234:8000` (admin).
2. Apps → **SOC Lab Detections**.
3. **Settings → Searches, reports, and alerts** → filter app `soclab_detections`.

### CLI
```bash
ssh namth@43.228.215.234
sudo -u splunk /opt/splunk/bin/splunk list saved-search -auth admin:<pass> | grep SOCLab
```

## Chạy 1 rule ngay (không chờ cron)

### GUI
1. Vào **Searches, reports, and alerts**.
2. Click tên rule → **Run**.
3. Kết quả hiện ở tab **Statistics**.

### CLI
```bash
sudo -u splunk /opt/splunk/bin/splunk dispatch \
  "SOCLab - T1059.001 - PowerShell Encoded Command" \
  -auth admin:<pass>
```

## Rule Table

| # | Name                            | Technique | Tactic              | Cron  | Severity |
|---|---------------------------------|-----------|---------------------|-------|----------|
| 1 | PowerShell Encoded Command      | T1059.001 | Execution           | */5m  | high     |
| 2 | Suspicious Cmd Chains           | T1059.003 | Execution           | */5m  | medium   |
| 3 | Registry Run Key Persistence    | T1547.001 | Persistence         | */5m  | high     |
| 4 | Scheduled Task Created          | T1053.005 | Persistence         | */5m  | medium   |
| 5 | LSASS Memory Access             | T1003.001 | Credential Access   | */5m  | critical |
| 6 | Brute Force Authentication      | T1110     | Credential Access   | */5m  | high     |
| 7 | Event Log Cleared               | T1070.001 | Defense Evasion     | */5m  | critical |
| 8 | Admin Share Lateral Movement    | T1021.002 | Lateral Movement    | */5m  | medium   |
| 9 | Account Discovery               | T1087     | Discovery           | */5m  | low      |
| 10| HTTP Beaconing                  | T1071.001 | Command and Control | */10m | high     |

Ngoài ra, auditd rules trên Linux endpoint cover thêm **T1055** (process injection via `-S execve` on user_exec) và **T1098** (account manipulation via `useradd_exec`/`usermod_exec`) — cộng lại **12 MITRE ATT&CK techniques**.

## Xem notable events

### GUI
Apps → **SOC Lab Detections** → Dashboards → **SOC Lab — Analyst Triage**.

Hoặc tìm trực tiếp:
```
index=notable
```

### CLI
```bash
sudo -u splunk /opt/splunk/bin/splunk search 'index=notable | table _time host mitre_technique severity rule_title' -auth admin:<pass> -earliest_time -24h
```

## Tune một rule

### GUI
1. **Settings → Searches, reports, and alerts** → click rule.
2. Chỉnh `Search`, `Cron`, `Threshold`.
3. **Save**.

### CLI (chỉnh file → restart)
```bash
sudo -u splunk vim /opt/splunk/etc/apps/soclab_detections/default/savedsearches.conf
sudo systemctl restart Splunkd
```

## Field extractions

Sysmon fields (`CommandLine`, `Image`, `TargetObject`, ...) được extract qua [`props.conf`](../splunk/apps/soclab_detections/default/props.conf). Nếu detection không match, verify bằng:

```
index=sysmon EventCode=1 | head 1 | table CommandLine Image ParentImage
```

Nếu field rỗng → check regex trong `props.conf`.
