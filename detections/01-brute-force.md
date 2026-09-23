# Detection 01 — Multiple Failed Login Attempts

## Scenario

This simulated detection focuses on identifying repeated Windows authentication failures that may indicate password guessing or brute-force activity.

## Data Source

Windows Security Event Logs

**Event ID:** 4625 — Failed Logon

## MITRE ATT&CK

**T1110 — Brute Force**

## SPL Detection Query

```spl
index=windows EventCode=4625
| stats count min(_time) as first_seen max(_time) as last_seen
  by Account_Name, Source_Network_Address
| where count >= 5
| sort - count
```

## Detection Logic

The query groups failed authentication attempts by username and source IP address.

Accounts with five or more failed authentication attempts are returned for further investigation.

A high number of authentication failures does not automatically confirm malicious activity. Possible legitimate causes include:

- Incorrect user passwords
- Expired credentials
- Misconfigured applications
- Automated services using old credentials

## Analyst Investigation

If this detection generates an alert, a SOC analyst should review:

1. The targeted user account
2. The source IP address
3. Number of failed authentication attempts
4. Time period of the activity
5. Whether multiple accounts were targeted
6. Whether a successful login occurred afterward
7. Additional activity associated with the account or source IP

## Possible Response Actions

If the activity is determined to be unauthorized:

- Reset the affected user's credentials
- Disable or temporarily lock the account
- Revoke active sessions
- Investigate the source system
- Block the suspicious IP address when appropriate
- Review additional authentication and endpoint logs
- Escalate the incident if account compromise is suspected

## Portfolio Note

This detection is based on simulated security events and is included to demonstrate SPL detection logic and SOC investigation methodology.
