# Investigation Notes

## Lab Summary

This investigation focused on evaluating two PowerShell-related security activity cases and determining the appropriate SOC disposition for each.

The first case represented routine administrative behavior, while the second introduced additional suspicious characteristics requiring deeper investigation. Windows Security Event ID 4688, Sysmon Event ID 1, and Wazuh Discover were used to validate process, user, and command-line context.

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
10. Compare both cases.
11. Determine the appropriate alert disposition.
12. Document the justification.

---

## Investigation Scenario

A Windows endpoint generates PowerShell-related security activity.

The analyst is unsure whether the alert represents:

- Normal administration
- Suspicious activity
- A genuine security incident

Two controlled cases are reviewed so that the analyst can compare the evidence and understand why similar-looking activity can result in different dispositions.

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

## DFIR Analysis

Case A demonstrated why a PowerShell alert should not automatically be escalated. The observed command was a normal administrative service-enumeration action without additional suspicious behavior.

Case B contained multiple indicators that increased the investigative significance of the activity. PowerShell was executed with `ExecutionPolicy Bypass`, followed by child-process creation through `cmd.exe`.

The individual indicators were not sufficient by themselves to prove malicious activity. The assessment was based on their combined context and was used to demonstrate a true-positive investigation workflow.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Execution | Windows Command Shell | T1059.003 |
| Discovery | System Information Discovery | T1082 |

---

## Analyst Observations

- PowerShell is a legitimate Windows administrative tool.
- An alert does not automatically equal an incident.
- User context is important during alert validation.
- Command-line parameters provide important behavioral context.
- Parent and child processes help reveal execution chains.
- Event ID 4688 provides process creation evidence.
- Sysmon Event ID 1 provides detailed process context.
- Wazuh allows centralized correlation of endpoint activity.
- Multiple weak indicators can become significant when they occur together.
- False-positive closure should be supported by evidence.
- True-positive escalation should also be supported by evidence.

---

## Investigation Assessment

### Case A

The observed activity represented routine administrative behavior and lacked additional suspicious indicators.

Disposition:

**False Positive / Benign Administrative Activity**

### Case B

The observed activity included `ExecutionPolicy Bypass` and additional child-process execution.

Disposition:

**True Positive Investigation Scenario / Escalate for Further Analysis**

---

## Conclusion

The investigation demonstrated how SOC analysts distinguish benign activity from potentially malicious behavior by correlating user context, command lines, process relationships, Windows telemetry, Sysmon, and Wazuh. The exercise reinforced that alert disposition should be based on the complete evidence and investigative context rather than a single suspicious-looking event.
