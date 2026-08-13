# Investigation Timeline

| Investigation Point | Case A | Case B |
|---|---|---|
| PowerShell Execution | Yes | Yes |
| Command | `Get-Service` | `ExecutionPolicy Bypass` |
| Child Process | None | `cmd.exe` |
| Related Activity | None observed | Additional process activity |
| Analyst Assessment | Benign | Suspicious |
| Final Disposition | False Positive | True Positive Scenario |

---

