# Investigation Timeline

## Lab 49 – False Positive vs True Positive Investigation

| Sequence | Activity | Case | Evidence |
|---|---|---|---|
| T1 | Wazuh agent status verified | Both | Wazuh Manager |
| T2 | Endpoint hostname identified | Both | PowerShell |
| T3 | Current user identified | Both | `whoami` |
| T4 | User SID identified | Both | `whoami /user` |
| T5 | Routine PowerShell activity generated | A | PowerShell |
| T6 | PowerShell process creation reviewed | A | Sysmon Event ID 1 |
| T7 | Windows process creation reviewed | A | Security Event ID 4688 |
| T8 | Case A correlated in Wazuh | A | Wazuh Discover |
| T9 | Case A assessed | A | Analyst |
| T10 | Test PowerShell script created | B | PowerShell |
| T11 | PowerShell executed with ExecutionPolicy Bypass | B | PowerShell / Sysmon |
| T12 | `cmd.exe` child process created | B | Sysmon Event ID 1 |
| T13 | Process creation reviewed | B | Security Event ID 4688 |
| T14 | Case B correlated in Wazuh | B | Wazuh Discover |
| T15 | Case A and Case B compared | Both | Analyst |
| T16 | Final alert dispositions documented | Both | Investigation |

---

# Case A Timeline

```text
User Identified
      ↓
PowerShell Started
      ↓
Get-Service Executed
      ↓
Process Creation Recorded
      ↓
Wazuh Telemetry Reviewed
      ↓
No Additional Suspicious Activity
      ↓
False Positive / Benign Activity
```

---

# Case B Timeline

```text
User Identified
      ↓
PowerShell Started
      ↓
ExecutionPolicy Bypass
      ↓
PowerShell Script Executed
      ↓
cmd.exe Spawned
      ↓
Process Creation Recorded
      ↓
Wazuh Telemetry Reviewed
      ↓
Multiple Suspicious Indicators Correlated
      ↓
True Positive Investigation Scenario
```

---

# Comparative Timeline

| Investigation Point | Case A | Case B |
|---|---|---|
| PowerShell Execution | Yes | Yes |
| Command | `Get-Service` | `ExecutionPolicy Bypass` |
| Child Process | None | `cmd.exe` |
| Related Activity | None observed | Additional process activity |
| Analyst Assessment | Benign | Suspicious |
| Final Disposition | False Positive | True Positive Scenario |

---

# Timeline Analysis

The investigation began by establishing the endpoint and user context for both cases.

Case A generated routine PowerShell activity involving service enumeration. Process telemetry from Windows and Sysmon was reviewed and correlated in Wazuh. No additional suspicious behavior was identified, resulting in a benign disposition.

Case B generated PowerShell activity using `ExecutionPolicy Bypass`, followed by child-process creation through `cmd.exe`. The additional execution context increased the significance of the activity and demonstrated a true-positive escalation workflow.

---

# Analyst Assessment

The timeline demonstrates that similar security alerts can have different outcomes depending on context.

Case A was closed as benign because the command, user context, and surrounding behavior were consistent with normal administration.

Case B was escalated because several indicators appeared together and required further investigation.

The final SOC decision should always be supported by the collected evidence rather than the alert title or a single suspicious parameter.
