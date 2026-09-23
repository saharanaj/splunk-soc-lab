# Investigation 01 - Brute Force Pattern

## Scenario
Synthetic Windows authentication data shows repeated Event ID 4625 failures against user `jsmith` from `10.10.20.55`, followed by a successful Event ID 4624 login.

## Triage
- Target account: `jsmith`
- Source IP: `10.10.20.55`
- Failed attempts: 7
- Successful login afterward: Yes
- Initial severity: Medium to High

## Analysis
The failed-login burst followed by successful authentication increases the possibility that password guessing succeeded. The source should be validated against known user devices, VPN ranges, and expected network segments.

## Recommended Response
- Validate the login with the account owner.
- Review the endpoint that originated the authentication attempts.
- Reset credentials if the activity is unauthorized.
- Revoke active sessions if compromise is confirmed.
- Review subsequent activity performed by the account.
- Consider blocking the source if appropriate.

## MITRE ATT&CK
- T1110 - Brute Force
- T1078 - Valid Accounts
