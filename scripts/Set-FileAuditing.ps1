# Windows File Auditing Configuration
# Based on: Malware Archaeology - Windows File Auditing Cheat Sheet ver Nov 2017
# Event ID 4663 - An attempt was made to access an object
# Run as Administrator

$ErrorActionPreference = 'Continue'
$log = "C:\SocLab\file-auditing-setup.log"
New-Item -ItemType Directory -Force -Path "C:\SocLab" | Out-Null

function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
    Add-Content -Path $log -Value $line
    Write-Host $line
}

Log "=== START: Windows File Auditing Setup (Malware Archaeology Cheat Sheet) ==="

# ============================================================
# STEP 1: Enable Object Access auditing (required for EID 4663)
# ============================================================
Log "[1] Enabling auditpol: Object Access > File System (Success)"
auditpol /set /subcategory:"File System" /success:enable /failure:disable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:disable
auditpol /get /subcategory:"File System" | Write-Host

# ============================================================
# STEP 2: Increase Security log size to 1GB (1,000,000 KB)
# ============================================================
Log "[2] Setting Security log size to 1,000,000 KB (1GB)"
wevtutil sl Security /ms:1024000000
wevtutil gl Security | Select-String "maxSize"

# ============================================================
# STEP 3: SACL helper function
# ============================================================
function Set-FolderAudit {
    param(
        [string]$Path,
        [bool]$Recurse = $false,
        [bool]$Remove = $false
    )

    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) {
        Log "  SKIP (not found): $Path"
        return
    }

    try {
        if ($Remove) {
            # Remove all audit ACEs (exclude)
            $acl = Get-Acl -Path $Path -Audit
            $acl.GetAuditRules($true, $true, [System.Security.Principal.NTAccount]) | ForEach-Object {
                $acl.RemoveAuditRule($_) | Out-Null
            }
            Set-Acl -Path $Path -AclObject $acl
            Log "  EXCLUDED: $Path"
            return
        }

        $acl = Get-Acl -Path $Path -Audit

        # Rights from cheat sheet: Create files/write data, Create folders/append data,
        # Write extended attributes, Delete, Change permissions, Take ownership
        $rights = [System.Security.AccessControl.FileSystemRights](
            "CreateFiles,WriteData,CreateDirectories,AppendData," +
            "WriteExtendedAttributes,Delete,ChangePermissions,TakeOwnership"
        )

        $inheritance = if ($Recurse) {
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
        } else {
            # "This folder and files only" - no subfolders
            [System.Security.AccessControl.InheritanceFlags]"ObjectInherit"
        }

        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        $auditFlags  = [System.Security.AccessControl.AuditFlags]::Success
        $everyone    = New-Object System.Security.Principal.NTAccount("Everyone")

        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $everyone, $rights, $inheritance, $propagation, $auditFlags
        )

        $acl.AddAuditRule($rule)
        Set-Acl -Path $Path -AclObject $acl

        $mode = if ($Recurse) { "This folder, subfolders and files" } else { "This folder and files ONLY" }
        Log "  SET [$mode]: $Path"

    } catch {
        Log "  ERROR on $Path : $_"
    }
}

# ============================================================
# STEP 4a: THIS FOLDER AND FILES ONLY (do NOT audit subfolders)
# ============================================================
Log "[3] Setting SACL - THIS FOLDER AND FILES ONLY"

$foldersShallow = @(
    "C:\Program Files",
    "C:\Program Files\Internet Explorer",
    "C:\Program Files\Common Files",
    "C:\Program Files (x86)",
    "C:\Program Files (x86)\Common Files",
    "C:\ProgramData",
    "C:\Windows",
    "C:\Windows\System32",
    "C:\Windows\System32\Drivers",
    "C:\Windows\System32\Drivers\etc",
    "C:\Windows\System32\Sysprep",
    "C:\Windows\System32\wbem",
    "C:\Windows\System32\WindowsPowerShell\v1.0",
    "C:\Windows\Web",
    "C:\Windows\SysWOW64",
    "C:\Windows\SysWOW64\Drivers",
    "C:\Windows\SysWOW64\wbem",
    "C:\Windows\SysWOW64\WindowsPowerShell\v1.0"
)

foreach ($folder in $foldersShallow) {
    Set-FolderAudit -Path $folder -Recurse $false
}

# ============================================================
# STEP 4b: THIS FOLDER, SUBFOLDERS AND FILES
# ============================================================
Log "[4] Setting SACL - THIS FOLDER, SUBFOLDERS AND FILES"

$foldersDeep = @(
    "C:\Boot",
    "C:\Perflogs",
    "C:\Users\Public",
    "C:\Windows\Scripts",
    "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup",
    "C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown",
    "C:\Windows\System32\GroupPolicy\User\Scripts\Logon",
    "C:\Windows\System32\GroupPolicy\User\Scripts\Logoff"
)

# Startup folder (common path)
$startupFolder = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

foreach ($folder in $foldersDeep) {
    Set-FolderAudit -Path $folder -Recurse $true
}
Set-FolderAudit -Path $startupFolder -Recurse $true

# Per-user AppData folders (wildcard expand)
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $user = $_.FullName
    @(
        "$user\AppData\Local",
        "$user\AppData\Local\Temp",
        "$user\AppData\LocalLow",
        "$user\AppData\Roaming"
    ) | ForEach-Object { Set-FolderAudit -Path $_ -Recurse $true }
}

# ============================================================
# STEP 5: EXCLUDE noisy folders (remove SACL inheritance)
# ============================================================
Log "[5] Removing SACL from noisy folders"

$noisyFolders = @(
    "C:\ProgramData\Microsoft\RAC\Temp",
    "C:\ProgramData\Microsoft\RAC\PublishedData",
    "C:\ProgramData\Microsoft\RAC\StateData",
    "C:\ProgramData\Microsoft\Search\Data\Applications\Windows"
)

Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $user = $_.FullName
    $noisyFolders += @(
        "$user\AppData\Local\Google\Chrome\User Data",
        "$user\AppData\Local\Microsoft\Windows\Explorer",
        "$user\AppData\Local\Microsoft\Windows\Temporary Internet Files",
        "$user\AppData\Local\Microsoft\Office",
        "$user\AppData\Local\Microsoft\Outlook",
        "$user\AppData\Local\Microsoft\Windows\PowerShell\CommandAnalysis",
        "$user\AppData\Local\Mozilla\Firefox\Profiles",
        "$user\AppData\LocalLow\Microsoft\CryptnetUrlCache",
        "$user\AppData\Roaming\Microsoft\Excel"
    )
}

foreach ($folder in $noisyFolders) {
    Set-FolderAudit -Path $folder -Remove $true
}

# ============================================================
# STEP 6: Enable Prefetch (forensic value)
# ============================================================
Log "[6] Enabling Prefetch/Superfetch"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" `
    -Name "EnableSuperfetch" -Value 3 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" `
    -Name "EnablePrefetcher" -Value 3 -Type DWord -ErrorAction SilentlyContinue
Log "  Prefetch/Superfetch enabled (value=3)"

# ============================================================
# STEP 7: Verify auditpol
# ============================================================
Log "[7] Final audit policy verification"
auditpol /get /category:"Object Access" | Where-Object { $_ -match "File System|Handle" }

Log "=== DONE: Check $log for details ==="
Log "=== Test: create a file in C:\Windows to generate EID 4663 ==="
