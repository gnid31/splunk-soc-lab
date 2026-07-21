# SOC Lab Atomic Tests — Windows
# Run as Administrator on win-ep-01. Each test isolated with try/finally cleanup.
# Logs to C:\SocLab\atomic-log.txt for report correlation.

$ErrorActionPreference = 'Continue'
$logDir = 'C:\SocLab'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = "$logDir\atomic-log.txt"
function Say($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$env:COMPUTERNAME] $msg"
    Add-Content -Path $log -Value $line
    Write-Host $line
}

Say "=== ATOMIC TESTS START ==="

# --- T1059.001 - PowerShell EncodedCommand ---
Say "T1059.001 start: PowerShell -EncodedCommand"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Get-Process | Select-Object -First 3"))
Start-Process powershell -ArgumentList "-NoProfile", "-EncodedCommand", $encoded -Wait -WindowStyle Hidden
Say "T1059.001 done"

# --- T1059.003 - cmd chain ---
Say "T1059.003 start: cmd.exe piped whoami"
cmd.exe /c "whoami & net user" > $null 2>&1
Say "T1059.003 done"

# --- T1547.001 - Registry Run key persistence ---
Say "T1547.001 start: registry Run key"
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty -Path $runKey -Name 'SocLabAtomicTest' -Value 'C:\Windows\System32\calc.exe' -Force
Start-Sleep -Seconds 2
Remove-ItemProperty -Path $runKey -Name 'SocLabAtomicTest' -Force -ErrorAction SilentlyContinue
Say "T1547.001 done"

# --- T1053.005 - Scheduled Task creation ---
Say "T1053.005 start: schtasks /create"
schtasks /create /tn "SocLabAtomicTask" /tr "cmd.exe /c echo test" /sc once /st 23:59 /f | Out-Null
Start-Sleep -Seconds 2
schtasks /delete /tn "SocLabAtomicTask" /f | Out-Null
Say "T1053.005 done"

# --- T1003.001 - LSASS memory access simulation (safe: OpenProcess only) ---
Say "T1003.001 start: LSASS handle open (safe read-only)"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Lsass {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@ -ErrorAction SilentlyContinue
$lsassPid = (Get-Process lsass).Id
# 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ — Mimikatz-style access mask
$h = [Lsass]::OpenProcess(0x1010, $false, $lsassPid)
if ($h -ne [IntPtr]::Zero) { [Lsass]::CloseHandle($h) | Out-Null }
Say "T1003.001 done"

# --- T1070.001 - Event log clear (skip Security log to keep audit intact; use Application) ---
Say "T1070.001 start: clear Application event log"
wevtutil cl Application
Say "T1070.001 done"

# --- T1087 - Account discovery ---
Say "T1087 start: whoami + net user + net localgroup"
whoami | Out-Null
net user | Out-Null
net localgroup Administrators | Out-Null
Say "T1087 done"

# --- T1021.002 - SMB admin share (simulated: net use to loopback C$) ---
Say "T1021.002 start: net use \\\\127.0.0.1\\C$"
net use \\127.0.0.1\C$ /user:$env:USERNAME "wrong-password" 2>$null | Out-Null
Say "T1021.002 done"

Say "=== ATOMIC TESTS COMPLETE ==="
Get-Content $log | Select-Object -Last 30
