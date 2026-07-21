# Troubleshooting

## Windows Sysmon events không tới `sysmon` index

**Symptom**: `index=sysmon | stats count` = 0.

**Cause**: UF service account không có quyền đọc Sysmon channel.

**Fix**:
```
# CLI (Ansible)
ansible win-ep-01 -m ansible.windows.win_shell -a 'sc.exe config SplunkForwarder obj= "LocalSystem"'
ansible win-ep-01 -m ansible.windows.win_service -a "name=SplunkForwarder state=restarted"

# GUI (services.msc): SplunkForwarder → Properties → Log On → Local System account.
```

## Windows events vào `main` thay vì `wineventlog`

**Cause**: MSI installer app `SplunkUniversalForwarder/local/inputs.conf` override system inputs.

**Fix**: đặt inputs override trong `apps/SplunkUniversalForwarder/local/inputs.conf` HOẶC dùng `system/local/inputs.conf` (precedence cao hơn). Playbook `03-windows-endpoint.yml` đã fix.

## Sysmon fields (CommandLine, Image, ...) rỗng

**Cause**: Splunk indexer chưa cài Add-on for Sysmon để extract fields.

**Fix**: `soclab_detections/default/props.conf` đã có regex extractions. Nếu không hoạt động:
```bash
# Verify props applied
sudo -u splunk /opt/splunk/bin/splunk btool props list "WinEventLog:Microsoft-Windows-Sysmon/Operational"

# Bounce splunk
sudo systemctl restart Splunkd
```

## Suricata service không start

**Symptom**: `systemctl is-active suricata` = failed.

**Cause**: interface `ens33` down, hoặc conflict với AppArmor.

**Fix**:
```bash
sudo journalctl -u suricata -n 50
sudo systemctl status suricata
# Common fix: run manually first
sudo suricata -c /etc/suricata/suricata.yaml -i ens33 -D
```

## Zeek không log

**Symptom**: `/opt/zeek/logs/current/*.log` không có file.

**Fix**:
```bash
sudo /opt/zeek/bin/zeekctl status
sudo /opt/zeek/bin/zeekctl deploy
```

## VPS Splunk Web không truy cập được từ ngoài

**Cause**: UFW / VPS provider firewall.

**Fix**:
```bash
sudo ufw allow 8000/tcp
# Nếu vẫn không được: check panel VPS provider để mở port.
```

## SSH key auth Windows không hoạt động

Đã document ở [00-setup.md](00-setup.md). Fallback: dùng password auth qua Ansible vault.

## Ansible ping Windows fails

Cần collection `ansible.windows`:
```bash
ansible-galaxy collection install ansible.windows community.windows
```

Dùng module `ansible.windows.win_ping` thay vì `ping`.
