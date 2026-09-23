# Detection 02 - Failed Logins Followed by Success

**Goal:** Identify repeated failed authentication attempts followed by a successful login.  
**Event IDs:** 4625, 4624  
**MITRE ATT&CK:** T1110 - Brute Force; T1078 - Valid Accounts

```spl
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures count(eval(EventCode=4624)) as successes values(Source_Network_Address) as src by Account_Name
| where failures >= 5 AND successes >= 1
```

This pattern deserves higher priority than failed logins alone because it may indicate that password guessing eventually succeeded.
