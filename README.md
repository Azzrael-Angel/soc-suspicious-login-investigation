# soc-suspicious-login-investigation
Beginner SOC lab investigating suspicious login activity using Windows Event Logs
# SOC Investigation: Suspicious Login Activity

## Objective
Investigate repeated failed login attempts and determine whether the account was compromised.

## Lab Setup
- Windows VM (Target system)
- Ubuntu VM (Analyst system)

## Tools Used
- Windows Event Viewer
- Wireshark (optional)
- VirtualBox

## Investigation Steps

### 1. Log Review
Checked Windows Security logs for:
- Event ID 4625 (failed logins)
- Event ID 4624 (successful logins)

### 2. Suspicious Activity Found
- Multiple failed login attempts in a short time
- Followed by a successful login
- Unknown source IP address

### 3. Timeline
- 02:13 — First failed login detected
- 02:15 — Repeated password attempts
- 02:18 — Successful login
- 02:20 — Alert triggered

## Findings
- Likely brute-force attack or password guessing attempt
- Account potentially compromised

## Recommendations
- Reset password immediately
- Enable MFA
- Monitor future login attempts

## Lessons Learned
- Failed login patterns can indicate brute-force attacks
- Event IDs are critical for investigation
