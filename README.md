# False Positive vs True Positive Investigation with Wazuh (DFIR Lab 49)

## Overview

Security alerts do not automatically represent security incidents. A SOC analyst must validate the alert, understand the user and process context, review the command line and related activity, and determine whether the behavior is legitimate or suspicious.

In this lab, two controlled PowerShell scenarios were investigated. The first represented normal administrative activity and was treated as a false positive. The second contained additional suspicious characteristics, including PowerShell ExecutionPolicy Bypass and child-process activity, and was treated as a true-positive investigation scenario.

Windows Security Event ID 4688, Sysmon Event ID 1, and Wazuh Discover were used to compare both cases and support the analyst disposition.

---

# Lab Objectives

- Understand false positives and true positives in SOC alert triage.
- Validate Wazuh alerts using endpoint evidence.
- Identify the user associated with suspicious activity.
- Analyze PowerShell command-line arguments.
- Examine parent and child process relationships.
- Review Windows Security Event ID 4688.
- Review Sysmon Event ID 1.
- Correlate Windows and Wazuh telemetry.
- Compare benign and suspicious activity.
- Produce an evidence-based alert disposition.

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

A Windows endpoint generates alerts associated with PowerShell activity. The SOC analyst must determine whether the alerts represent routine administration or potentially unauthorized activity.

Two controlled cases are investigated:

### Case A – False Positive

- Expected administrative context
- Routine PowerShell command
- No suspicious child process
- No related malicious activity

### Case B – True Positive Scenario

- PowerShell execution with `ExecutionPolicy Bypass`
- Additional child-process activity
- Additional endpoint telemetry requiring investigation
- Behavior inconsistent with the expected administrative baseline

The objective is to determine why the first case can be safely closed while the second should be escalated for further investigation.

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

# Key Findings

- PowerShell activity alone does not indicate malicious behavior.
- Case A represented routine administrative activity.
- Case B introduced additional suspicious execution characteristics.
- Event ID 4688 provided Windows process creation evidence.
- Sysmon Event ID 1 provided detailed process relationships.
- Wazuh Discover allowed centralized correlation of endpoint activity.
- User context and command-line information were important to both cases.
- The second case required escalation because multiple indicators aligned.

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

# DFIR Value

False-positive and true-positive analysis is a core SOC skill. An alert should not be closed simply because the executable or command is legitimate, and it should not be escalated solely because a suspicious-looking string appears.

The analyst must consider:

- User
- Time
- Command
- Parent process
- Child process
- Business purpose
- Related activity
- Endpoint context

The final disposition should be based on the totality of evidence.

---

# Skills Practiced

- SOC Alert Triage
- False Positive Analysis
- True Positive Analysis
- PowerShell Investigation
- User Attribution
- Process Tree Analysis
- Event ID 4688
- Sysmon Event ID 1
- Wazuh Discover
- Evidence Correlation
- Timeline Reconstruction
- Analyst Disposition
- DFIR Documentation

---

# MITRE ATT&CK Context

Potentially relevant techniques include:

- **T1059.001 – PowerShell**
- **T1059.003 – Windows Command Shell**
- **T1082 – System Information Discovery**

The ATT&CK mapping must be based on the actual activity observed rather than assuming that PowerShell execution is malicious.

---

# Outcome

Successfully compared benign administrative PowerShell activity with a suspicious PowerShell execution scenario.

The investigation demonstrated how Windows process telemetry, user context, command-line analysis, child-process relationships, Sysmon, and Wazuh can be combined to determine whether a security alert should be closed as a false positive or escalated as a true positive.
