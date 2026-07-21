# Setup Guide — Splunk SOC Lab

Hạ tầng: 1 VPS (Splunk server) + 1 Ubuntu VM + 1 Windows VM.

## 1. Prerequisites

Trên máy controller (Kali/Linux):

```bash
sudo apt-get install -y ansible sshpass
ansible-galaxy collection install ansible.windows community.windows
```

Sinh SSH key riêng cho lab:

```bash
ssh-keygen -t ed25519 -N '' -f ~/.ssh/soclab_ed25519 -C 'soclab-ansible-controller'
```

## 2. Inventory

Chỉnh `ansible/inventory/hosts.ini` với IP + user của bạn. Mặc định:

| Host          | IP                | User  | Kết nối          |
|---------------|-------------------|-------|------------------|
| splunk-vps    | 43.228.215.234    | namth | SSH key          |
| linux-ep-01   | 192.168.154.166   | gnid  | SSH key          |
| win-ep-01     | 192.168.154.164   | gnid  | SSH + password vault |

## 3. Push SSH key to Linux hosts

### GUI (SecureCRT / MobaXterm)
1. Mở kết nối SSH bằng password lần đầu.
2. Copy nội dung `~/.ssh/soclab_ed25519.pub` vào `~/.ssh/authorized_keys` trên remote.
3. `chmod 600 ~/.ssh/authorized_keys`.

### CLI
```bash
ssh-copy-id -i ~/.ssh/soclab_ed25519.pub namth@43.228.215.234
ssh-copy-id -i ~/.ssh/soclab_ed25519.pub gnid@192.168.154.166
```

## 4. Windows Endpoint SSH

Windows 10/11 phải có OpenSSH Server (sẵn từ Win10 1809+).

### GUI
1. Settings → Apps → Optional Features → Add → "OpenSSH Server".
2. Services → OpenSSH SSH Server → Start + Set Automatic.
3. Windows Defender Firewall → Allow inbound TCP 22.

### CLI (PowerShell as Admin)
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

Grant user Administrators (nếu cài Splunk/Sysmon):
```powershell
net localgroup Administrators gnid /add
```

## 5. Ansible Vault

Windows password lưu vault:

```bash
echo "your_vault_password_here" > ~/.soclab_vault_pass
chmod 600 ~/.soclab_vault_pass

cd ansible
cp inventory/group_vars/windows_endpoints/vault.yml.example inventory/group_vars/windows_endpoints/vault.yml
# Chỉnh password thật trong vault.yml
ansible-vault encrypt inventory/group_vars/windows_endpoints/vault.yml
```

## 6. Ping test

```bash
cd ansible
ansible splunk_server -m ping
ansible linux_endpoints -m ping
ansible windows_endpoints -m ansible.windows.win_ping
```

Kết quả mong đợi: 3 host đều `SUCCESS`.

## 7. Deploy stack

```bash
ansible-playbook playbooks/site.yml
```

Chạy tuần tự:
1. `01-splunk-server.yml` — cài Splunk Enterprise trên VPS
2. `02-linux-endpoint.yml` — UF + Suricata + Zeek + auditd trên Ubuntu
3. `03-windows-endpoint.yml` — UF + Sysmon trên Windows
4. `04-detections.yml` — deploy 10 SPL correlation searches + dashboard

## 8. Truy cập Splunk Web

- URL: `http://43.228.215.234:8000`
- User: `admin`
- Pass: xem trong `group_vars/all.yml` (nên thay đổi ngay lần đầu).
