# Atomic Red Team — Chạy và xác nhận detection

## Prerequisites

- Windows endpoint: `gnid` là Administrator (đã set).
- Linux endpoint: có `sudo`. Cần `sshpass` cho T1110 test (`apt install sshpass`).

## Chạy toàn bộ tests

### GUI (từ máy remote qua RDP/console)
1. Copy `atomic-tests/run-all-windows.ps1` sang Windows endpoint (RDP, share).
2. Mở **PowerShell as Administrator**.
3. `Set-ExecutionPolicy -Scope Process Bypass`.
4. `.\run-all-windows.ps1`.

### CLI (Ansible từ Kali)
```bash
cd ~/splunk-soc-lab/ansible

# Push scripts to endpoints
ansible win-ep-01 -m ansible.windows.win_copy -a 'src=../atomic-tests/run-all-windows.ps1 dest=C:/SocLab/run-atomic.ps1'
ansible linux-ep-01 -m copy -a 'src=../atomic-tests/run-all-linux.sh dest=/opt/soclab-atomic.sh mode=0755' --become

# Run
ansible win-ep-01 -m ansible.windows.win_shell -a 'powershell -ExecutionPolicy Bypass -File C:/SocLab/run-atomic.ps1'
ansible linux-ep-01 -m shell -a '/opt/soclab-atomic.sh' --become
```

## Xác nhận detection fired

Chờ ~1 phút cho events tới Splunk + cron chạy, sau đó:

### GUI
Vào dashboard **SOC Lab — Analyst Triage**, chọn time range **Last 15 minutes**. Xem panel "Recent Notable Events" — mỗi test nên có 1+ row.

### CLI
```bash
ssh namth@43.228.215.234
sudo -u splunk /opt/splunk/bin/splunk search \
  'index=notable earliest=-15m | stats count by mitre_technique' \
  -auth admin:<pass>
```

## Expected match table

| Test | Detection rule                       | Confirm SPL |
|------|---------------------------------------|-------------|
| T1059.001 encoded PS | PowerShell Encoded Command | `index=sysmon EventCode=1 CommandLine="*EncodedCommand*"` |
| T1059.003 cmd chain  | Suspicious Cmd Chains      | `index=sysmon EventCode=1 Image="*cmd.exe" _raw="*&whoami*"` |
| T1547.001 Run key    | Registry Run Key Persistence | `index=sysmon EventCode=13 TargetObject="*Run*"` |
| T1053.005 schtasks   | Scheduled Task Created     | `index=wineventlog EventCode=4698` |
| T1003.001 LSASS      | LSASS Memory Access        | `index=sysmon EventCode=10 TargetImage="*lsass.exe"` |
| T1110 brute force    | Brute Force Authentication | `index=linux_auditd sourcetype=linux:auth "Failed password"` |
| T1070.001 log clear  | Event Log Cleared          | `index=wineventlog (EventCode=1102 OR EventCode=104)` |
| T1021.002 admin share| Admin Share Lateral Movement | `index=wineventlog EventCode=4624 LogonType=3` |
| T1087 discovery      | Account Discovery          | `index=sysmon EventCode=1 Image="*whoami.exe" OR Image="*net.exe"` |
| T1071.001 beacon     | HTTP Beaconing             | `index=zeek source=*conn.log` |

## Cleanup

Windows test tự cleanup (Remove-ItemProperty, schtasks /delete). Linux test cũng cleanup user tạo ra.

Manual verify:
```powershell
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
schtasks /query /tn "SocLabAtomicTask"
```

## Tuning (giảm false positive)

Sau khi chạy tests và có false positives từ activity thường, chỉnh savedsearches.conf:

- Thêm điều kiện `NOT ParentImage="*known-tool*"` để loại trừ tool hợp lệ.
- Tăng threshold cho brute-force nếu 10 fail/5m quá thấp cho môi trường.
- Log các exception vào `docs/03-tuning-log.md`.
