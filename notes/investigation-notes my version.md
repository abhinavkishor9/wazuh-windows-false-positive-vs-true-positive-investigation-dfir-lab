# Investigation Notes

## Lab Summary

This investigation focused on evaluating two PowerShell-related security activity cases and determining the appropriate SOC disposition for each.

---

## Analyst Methodology

1. Verify Wazuh agent connectivity.
2. Establish endpoint and user context.
3. Generate benign administrative PowerShell activity.
4. Investigate the first case using Windows telemetry.
5. Correlate Case A in Wazuh.
6. Generate the second controlled PowerShell activity.
7. Introduce additional process context.
8. Investigate Case B using Sysmon and Security logs.
9. Correlate Case B in Wazuh.

---

## Investigation Scenario

A Windows endpoint generates a security alert associated with PowerShell activity. The SOC analyst cannot determine from the alert alone whether the activity was legitimate administration or potentially malicious behavior.

The analyst investigates two cases and compares:

User identity and expected role
Execution time
PowerShell command
Parent and child processes
Related Windows events
Wazuh telemetry
Additional activity surrounding the alert

The objective is to determine which case can be safely closed as a false positive and which contains sufficient evidence to justify true-positive escalation.

---

## Evidence Collected

### Evidence 1 – Endpoint Context

Commands Used:

```powershell
hostname
```

```powershell
whoami
```

```powershell
whoami /user
```

Finding:

Established the Windows host, active user, and user SID before investigating the activity.

---

### Evidence 2 – Case A Administrative Activity

Commands Used:

```powershell
Get-Service
```

```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
```

Finding:

Generated a normal administrative PowerShell activity pattern based on service enumeration.

---

### Evidence 3 – Case A Process Creation

Event Sources:

- Windows Security Event ID 4688
- Sysmon Event ID 1

Finding:

Confirmed PowerShell process creation and provided process execution context.

---

### Evidence 4 – Case A Wazuh Correlation

Search Used:

```text
agent.name: DESKTOP-9MMM37V AND powershell.exe
```

Finding:

Wazuh provided centralized visibility into the PowerShell activity.

---

### Evidence 5 – Case B Script

Command Used:

```powershell
@'
Write-Output "SOC Lab Test"
'@ | Set-Content C:\FPvsTP-Test.ps1
```

Finding:

Created a harmless PowerShell script for the second investigation scenario.

---

### Evidence 6 – Case B PowerShell Execution

Command Used:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\FPvsTP-Test.ps1
```

Finding:

Generated PowerShell activity containing the `ExecutionPolicy Bypass` parameter.

This provided an additional investigative indicator compared with Case A.

---

### Evidence 7 – Case B Child Process

Command Used:

```powershell
Start-Process cmd.exe
```

Finding:

Created a PowerShell-to-CMD process relationship for further investigation.

---

### Evidence 8 – Case B Process Creation

Event Sources:

- Sysmon Event ID 1
- Windows Security Event ID 4688

Finding:

PowerShell and child-process activity were examined to reconstruct the process relationship.

---

### Evidence 9 – Case B Wazuh Correlation

Searches Used:

```text
agent.name: DESKTOP-9MMM37V AND powershell
```

```text
agent.name: DESKTOP-9MMM37V AND ExecutionPolicy
```

```text
agent.name: DESKTOP-9MMM37V AND cmd.exe
```

Finding:

Wazuh provided centralized visibility into the PowerShell and child-process activity.

---

## Evidence Comparison

| Investigation Point | Case A | Case B |
|---|---|---|
| PowerShell | Present | Present |
| Command | `Get-Service` | ExecutionPolicy Bypass |
| Child Process | None | `cmd.exe` |
| User Context | Expected | Requires investigation |
| Related Activity | None observed | Additional process activity |
| Wazuh Telemetry | PowerShell | PowerShell + child process |
| Analyst Disposition | False Positive | True Positive Scenario |

---


## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Execution | Windows Command Shell | T1059.003 |
| Discovery | System Information Discovery | T1082 |

---

