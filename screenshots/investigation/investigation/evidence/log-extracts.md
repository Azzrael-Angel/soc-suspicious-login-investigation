# Log Evidence (Simulated for Lab)

## Windows Security Event Logs

### Event ID 4625 - Failed Logon
- Username: employee01
- Source IP: 192.168.1.50
- Time: 02:13 - 02:17
- Failure Reason: Incorrect password

### Observations
- 25 failed login attempts within 4 minutes
- Same username targeted repeatedly
- Pattern consistent with brute-force activity

---

### Event ID 4624 - Successful Logon
- Username: employee01
- Source IP: 192.168.1.50 (same as failed attempts)
- Time: 02:18
- Logon Type: Interactive

### Observations
- Successful login immediately after repeated failures
- High suspicion of credential compromise
