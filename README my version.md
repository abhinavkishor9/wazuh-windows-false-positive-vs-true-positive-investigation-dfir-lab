# wazuh-windows-false-positive-vs-true-positive-investigation-dfir-lab
## Overview

A false positive is an alert that looks suspicious according to a detection rule but, after investigation, turns out to be legitimate activity.

Example:

Wazuh Alert
   ↓
PowerShell executed
   ↓
User: Administrator
   ↓
Known maintenance activity
   ↓
Expected command
   ↓
No suspicious follow-on activity

The alert was real—the PowerShell execution happened—but the security interpretation was incorrect.

Therefore:

A false positive is not necessarily a "bad log." It is a legitimate event incorrectly treated as malicious.

A true positive is an alert where investigation confirms that the detected behavior is actually suspicious or malicious.

Example:

Wazuh Alert
   ↓
PowerShell execution
   ↓
Unexpected user
   ↓
Suspicious command
   ↓
Encoded/obfuscated activity
   ↓
Unexpected child process
   ↓
Network connection

Now multiple pieces of evidence support the alert.

The same Windows activity can be either legitimate or malicious.

For example:

PowerShell.exe

could mean:

Legitimate
Administrator
+
9:00 AM
+
IT maintenance
+
Expected script

or:

Suspicious
Normal user
+
2:30 AM
+
Encoded command
+
Unexpected child process

The executable is identical.

Context changes the verdict.

Case A – False Positive

A known administrative user executes a legitimate PowerShell command during an expected maintenance activity.

Case B – True Positive

We'll generate a suspicious-looking PowerShell execution with additional contextual indicators so that the second case requires escalation.

We will not use malware.

The difference will come from the context and correlated evidence.

In this lab, two controlled PowerShell scenarios were investigated. The first represented normal administrative activity and was treated as a false positive. The second contained additional suspicious characteristics, including PowerShell ExecutionPolicy Bypass and child-process activity, and was treated as a true-positive investigation scenario.

Windows Security Event ID 4688, Sysmon Event ID 1, and Wazuh Discover were used to compare both cases and support the analyst disposition.

---

# Lab Objectives

- Establish whether a triggered alert represents expected or unexpected endpoint behavior.
- Determine the identity and context of the user involved in each case.
- Compare command-line characteristics between benign and suspicious executions.
- Examine process ancestry and follow-on child processes.
- Validate alert evidence across independent Windows telemetry sources.
- Assess the significance of individual indicators when viewed in context.
- Develop a defensible analyst disposition for each alert.
- Document the reasoning supporting closure or escalation.

---

# Lab Environment

| Component          | Value                                      |
| ------------------ | ------------------------------------------ |
| Host OS            | Windows 11 Pro                             |
| SIEM               | Wazuh 4.12                                 |
| Endpoint Agent     | Wazuh Agent                                |
| Endpoint Name      | DESKTOP-9MMM37V                            |
| Agent ID           | 001                                        |
| Investigation Type | False Positive vs True Positive Analysis   |
| Primary Activity   | PowerShell                                 |
| Supporting Events  | Security 4688 / Sysmon 1                  |
| Investigation UI   | Wazuh Discover                             |

---

# Tools Used

- PowerShell
- Windows Event Viewer
- Windows Security Event ID 4688
- Sysmon Event ID 1
- Wazuh Discover
- Wazuh Agent

---

# Investigation Scenario

A Windows endpoint generates a security alert associated with PowerShell activity. The SOC analyst cannot determine from the alert alone whether the activity was legitimate administration or potentially malicious behavior.

The analyst investigates two cases and compares:

- User identity and expected role
- Execution time
- PowerShell command
- Parent and child processes
- Related Windows events
- Wazuh telemetry
- Additional activity surrounding the alert

The objective is to determine which case can be safely closed as a false positive and which contains sufficient evidence to justify true-positive escalation.

---

# Investigation Workflow

```text
Wazuh Alert
    ↓
Validate Alert
    ↓
Identify User
    ↓
Identify Process
    ↓
Review Command Line
    ↓
Check Parent / Child Processes
    ↓
Review Timeline
    ↓
Correlate Windows + Sysmon + Wazuh
    ↓
Compare Against Expected Behavior
    ↓
False Positive OR True Positive
    ↓
Analyst Disposition
```

---

# Investigation Steps

### Step 1 – Verify Wazuh Agent

On the Wazuh server:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Confirm the endpoint is active.

---

### Step 2 – Establish Endpoint Context

On Windows:

```powershell
hostname
```

```powershell
whoami
```

```powershell
whoami /user
```

Record:

- Hostname
- Username
- User SID

---

### Step 3 – Generate Case A: Benign Administrative Activity

Run:

```powershell
Get-Service
```

Then:

```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
```

This represents routine administrative service enumeration.

Record the execution time.

---

### Step 4 – Investigate Case A in Sysmon

Open:

```text
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational
```

Search for:

```text
Event ID 1 – Process Creation
```

Review:

- Image
- CommandLine
- ParentImage
- User
- ProcessId
- Timestamp

---

### Step 5 – Investigate Case A in Windows Security

Open:

```text
Event Viewer
→ Windows Logs
→ Security
```

Search:

```text
Event ID 4688
```

Review the PowerShell process creation event.

---

### Step 6 – Investigate Case A in Wazuh

Search Wazuh Discover:

```text
agent.name: DESKTOP-9MMM37V
```

Then:

```text
agent.name: DESKTOP-9MMM37V AND powershell.exe
```

Review the relevant event and record:

- Timestamp
- User
- Command line
- Parent process
- Process ID

---

### Step 7 – Assess Case A

The activity should be evaluated against:

- Expected user
- Expected administrative purpose
- Normal command
- Absence of suspicious child processes
- Absence of suspicious follow-on activity

Disposition:

```text
False Positive / Benign Administrative Activity
```

---

### Step 8 – Generate Case B

Create a harmless PowerShell script:

```powershell
@'
Write-Output "SOC Lab Test"
'@ | Set-Content C:\FPvsTP-Test.ps1
```

Verify:

```powershell
Get-Content C:\FPvsTP-Test.ps1
```

---

### Step 9 – Execute Case B With ExecutionPolicy Bypass

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\FPvsTP-Test.ps1
```

This remains harmless test activity, but introduces an investigative indicator that requires validation.

---

### Step 10 – Generate Child Process Activity

Run:

```powershell
Start-Process cmd.exe
```

This creates a process relationship:

```text
powershell.exe
      ↓
cmd.exe
```

---

### Step 11 – Investigate Case B With Sysmon

Review:

```text
Sysmon Operational
→ Event ID 1
```

Identify:

- PowerShell
- `ExecutionPolicy Bypass`
- `cmd.exe`
- User
- ParentImage
- CommandLine
- ProcessId
- ParentProcessId
- Timestamp

---

### Step 12 – Investigate Case B With Security Event 4688

Search:

```text
Event ID 4688
```

Compare the PowerShell process with the child `cmd.exe` process.

---

### Step 13 – Investigate Case B in Wazuh

Search:

```text
agent.name: DESKTOP-9MMM37V AND powershell
```

Then:

```text
agent.name: DESKTOP-9MMM37V AND ExecutionPolicy
```

And:

```text
agent.name: DESKTOP-9MMM37V AND cmd.exe
```

Where available, use:

```text
data.win.eventdata.commandLine:*ExecutionPolicy*
```

---

# Case Comparison

| Investigation Point | Case A | Case B |
|---|---|---|
| Activity | Routine PowerShell | Suspicious PowerShell |
| Command | `Get-Service` | `ExecutionPolicy Bypass` |
| User Context | Expected | Requires validation |
| Child Process | None | `cmd.exe` |
| Security Impact | Low | Requires investigation |
| Related Activity | None observed | Additional process activity |
| Wazuh Evidence | PowerShell activity | PowerShell + child process |
| Disposition | False Positive | True Positive Scenario |

---



# Evidence Correlation

| Evidence | Source | Investigation Value |
|---|---|---|
| Hostname | PowerShell | Identifies endpoint |
| User | `whoami` | Establishes account context |
| Command Line | Sysmon / Security | Shows how PowerShell was executed |
| Process Creation | Event ID 4688 | Confirms process execution |
| Parent Process | Sysmon | Establishes process relationship |
| Child Process | Sysmon | Identifies follow-on activity |
| Wazuh Event | Wazuh Discover | Centralized endpoint telemetry |
| Timeline | Analyst | Supports disposition |

---

# MITRE ATT&CK Context

Potentially relevant techniques include:

- **T1059.001 – PowerShell**
- **T1059.003 – Windows Command Shell**
- **T1082 – System Information Discovery**

The ATT&CK mapping must be based on the actual activity observed rather than assuming that PowerShell execution is malicious.

---

