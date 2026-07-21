# Atomic Red Team — Detection Validation

10 adversary emulation tests to validate the SPL correlation searches. Each test:
- Maps to one MITRE ATT&CK technique
- Has clear execute / cleanup steps
- Documents IOC + IOA + expected Splunk detection

Run from the endpoint. Requires **elevated shell** (admin/root) — always in an isolated lab VM, never production.

## Test Matrix

| # | Technique | Test                                     | Platform | Expected Detection Rule           |
|---|-----------|------------------------------------------|----------|-----------------------------------|
| 1 | T1059.001 | PowerShell -EncodedCommand               | Windows  | SOCLab - T1059.001                |
| 2 | T1059.003 | cmd.exe piped whoami/net user            | Windows  | SOCLab - T1059.003                |
| 3 | T1547.001 | Registry Run key persistence             | Windows  | SOCLab - T1547.001                |
| 4 | T1053.005 | schtasks /create                         | Windows  | SOCLab - T1053.005                |
| 5 | T1003.001 | LSASS handle w/ ProcDump-like access mask| Windows  | SOCLab - T1003.001                |
| 6 | T1110     | 15x failed SSH from LAN → linux-ep-01    | Linux    | SOCLab - T1110                    |
| 7 | T1070.001 | wevtutil cl Security                     | Windows  | SOCLab - T1070.001                |
| 8 | T1021.002 | net use \\\\host\\C$ w/ new credential   | Windows  | SOCLab - T1021.002                |
| 9 | T1087     | whoami + net user + net localgroup       | Windows  | SOCLab - T1087                    |
| 10| T1071.001 | curl loop to public IP every 30s (10x)   | Linux    | SOCLab - T1071.001                |

## Runbook

Windows tests: run `run-all-windows.ps1` in PowerShell as Administrator.
Linux tests: run `bash run-all-linux.sh` with sudo.

Both scripts log start/end timestamps for correlation with Splunk detections.
