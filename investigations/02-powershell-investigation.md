# Investigation 02 - Suspicious PowerShell

## Scenario
A synthetic PowerShell Script Block Logging event contains an encoded-command pattern.

## Triage
- User: `labuser`
- Host: `WIN-LAB01`
- Event ID: 4104
- Suspicious indicator: `-EncodedCommand`
- Initial severity: Medium

## Analysis
Encoded PowerShell can be used legitimately, but it is also frequently used to obscure command content. The event should be correlated with process creation, network activity, user context, and change-management records.

## Recommended Response
- Decode the command safely for review.
- Identify the parent process.
- Review nearby process and network events.
- Validate whether the user or administrator expected the activity.
- Isolate the endpoint if malicious execution is confirmed.

## MITRE ATT&CK
- T1059.001 - PowerShell
