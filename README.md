# Splunk SOC Detection Portfolio

Simulation-based Security Operations Center (SOC) portfolio demonstrating Splunk SPL, Windows security-event analysis, incident investigation, and MITRE ATT&CK mapping.

> **Project Type:** Simulation / Cybersecurity Portfolio  
> **Data:** Synthetic security events created for learning and demonstration purposes.

## Objective

The purpose of this project is to demonstrate SOC analyst workflows using simulated Windows security events and Splunk Search Processing Language (SPL).

This portfolio focuses on developing detection logic, analyzing suspicious activity, investigating security events, mapping findings to MITRE ATT&CK, and recommending appropriate response actions.

## Skills Demonstrated

- Splunk Search Processing Language (SPL)
- SIEM Detection Logic
- Windows Security Event Analysis
- Log Analysis
- Threat Detection
- Security Monitoring
- Incident Triage
- Incident Investigation
- MITRE ATT&CK Mapping
- Security Documentation

## Detection Scenarios

1. Multiple Failed Login Attempts / Brute Force
2. Failed Logins Followed by Successful Authentication
3. Suspicious PowerShell Execution
4. New User Account Creation
5. Privileged Group Membership Changes

---

## Detection 1 — Multiple Failed Logins

**Windows Event ID:** 4625  
**MITRE ATT&CK:** T1110 — Brute Force

### SPL

```spl
index=windows EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count >= 5
| sort - count
```

### Analyst Approach

Repeated authentication failures from the same source may indicate password guessing or brute-force activity.

An analyst should review:

- Targeted account
- Source IP address
- Number of failed attempts
- Authentication time window
- Successful logins following the failures
- Related activity from the same account or source

---

## Detection 2 — Failed Logins Followed by Success

**Windows Event IDs:** 4625 and 4624  
**MITRE ATT&CK:** T1110 — Brute Force / T1078 — Valid Accounts

### SPL

```spl
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures
        count(eval(EventCode=4624)) as successes
        by Account_Name
| where failures >= 5 AND successes >= 1
```

A successful authentication following repeated failed attempts may indicate that password guessing eventually succeeded.

---

## Detection 3 — Suspicious PowerShell Activity

**Windows Event ID:** 4104  
**MITRE ATT&CK:** T1059.001 — PowerShell

### SPL

```spl
index=windows EventCode=4104
| search ScriptBlockText="*EncodedCommand*"
    OR ScriptBlockText="*IEX*"
    OR ScriptBlockText="*DownloadString*"
| table _time Computer User ScriptBlockText
```

Encoded or remotely downloaded PowerShell commands may require additional investigation.

---

## Detection 4 — New User Account Creation

**Windows Event ID:** 4720  
**MITRE ATT&CK:** T1136.001 — Local Account

### SPL

```spl
index=windows EventCode=4720
| table _time Computer SubjectUserName TargetUserName
| sort - _time
```

Unexpected account creation should be reviewed to determine whether the activity was authorized.

---

## Detection 5 — Privileged Group Membership Change

**Windows Event ID:** 4732  
**MITRE ATT&CK:** T1098 — Account Manipulation

### SPL

```spl
index=windows EventCode=4732
| table _time Computer SubjectUserName MemberName GroupName
| sort - _time
```

Unexpected additions to privileged groups such as Administrators may indicate privilege escalation or persistence.

---

## Investigation Workflow

For each security alert, a SOC analyst should:

1. Review the triggering event.
2. Identify the affected account and system.
3. Determine the source of the activity.
4. Review related security events.
5. Compare the activity with expected user behavior.
6. Map suspicious activity to MITRE ATT&CK.
7. Determine the severity of the incident.
8. Recommend containment or remediation actions.

## Recommended Response Actions

Depending on the investigation, possible actions may include:

- Reset compromised credentials
- Disable suspicious accounts
- Revoke active sessions
- Block malicious IP addresses
- Isolate affected endpoints
- Review additional endpoint and network logs
- Escalate confirmed incidents for incident response

## Disclaimer

This repository is a simulation-based cybersecurity portfolio project. The events and scenarios are synthetic and intended for educational and professional-development purposes.
