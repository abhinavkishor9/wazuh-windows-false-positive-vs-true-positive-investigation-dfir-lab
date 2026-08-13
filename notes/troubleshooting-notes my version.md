# Troubleshooting Notes

## Issue 1 – Wazuh Agent Not Active

### Problem

The Windows endpoint did not appear to be reporting normally in Wazuh.

### Check

Run on the Wazuh server:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

### Resolution

Verify that the agent status is `Active` before continuing with the investigation.

---

## Issue 2 – PowerShell Activity Not Found in Wazuh

### Problem

The PowerShell activity was visible locally but not immediately found in Wazuh Discover.

### Possible Causes

- Event collection delay
- Different Wazuh field mapping
- Relevant Windows event channel not being collected
- Search query too restrictive

### Resolution

Start with:

```text
agent.name: DESKTOP-9MMM37V
```

Then narrow using:

```text
powershell.exe
```

Inspect an actual event to determine the correct fields.

---

## Issue 3 – Event ID 4688 Not Available

### Problem

The expected process creation event was not visible in the Windows Security log.

### Cause

Process creation auditing may not be enabled, or older events may have been overwritten.

### Resolution

Check the Security log for Event ID 4688 and use Sysmon Event ID 1 as a complementary source when available.

Document missing telemetry as an investigation limitation.

---

## Issue 4 – Sysmon Event ID 1 Not Found

### Problem

PowerShell execution was visible, but Sysmon did not show the expected process creation event.

### Cause

Possible causes include:

- Sysmon service not running
- Sysmon configuration issue
- Event collection delay
- Event log filtering

### Check

```powershell
Get-Service Sysmon64
```

Then review:

```text
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational
```

---

## Issue 5 – ExecutionPolicy Bypass Was Not Visible

### Problem

The process creation event did not show the expected `-ExecutionPolicy Bypass` parameter.

### Cause

Command-line auditing may not be enabled or the Wazuh event may not contain the complete command line.

### Resolution

Use Sysmon Event ID 1 when available because it can provide detailed command-line information.

Do not assume the parameter existed if the evidence does not show it.

---

## Issue 6 – Child Process Not Visible

### Problem

`cmd.exe` was started, but the expected parent-child relationship was not immediately obvious.

### Resolution

Correlate:

- Process ID
- ParentProcessId
- ParentImage
- Image
- Timestamp

Use Sysmon Event ID 1 where available.

---

## Issue 7 – Too Many Wazuh Results

### Problem

Searching only for:

```text
agent.name: DESKTOP-9MMM37V
```

returned many unrelated events.

### Resolution

Narrow the search using:

```text
agent.name: DESKTOP-9MMM37V AND powershell
```

Then:

```text
agent.name: DESKTOP-9MMM37V AND cmd.exe
```

Use the investigation time window to further reduce unrelated events.

---

## Issue 8 – False Positive and True Positive Cases Look Similar

### Problem

Both cases involve PowerShell.

### Explanation

PowerShell is a legitimate administrative tool and can be present in both benign and malicious activity.

### Resolution

Compare the full context:

```text
User
+
Time
+
Command
+
Parent Process
+
Child Process
+
Related Events
+
Business Purpose
```

Do not classify the case based only on the presence of `powershell.exe`.

---

## Issue 9 – True Positive Classification Requires More Evidence

### Problem

`ExecutionPolicy Bypass` appears suspicious, but legitimate administrators can also use it.

### Resolution

Treat it as an investigative indicator rather than automatic proof of compromise.

Look for supporting evidence such as:

- Unexpected user
- Unusual time
- Suspicious parent process
- Unexpected child process
- Network activity
- Persistence
- Other Wazuh alerts

---

