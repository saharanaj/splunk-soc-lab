# Detection 01 - Multiple Failed Logins

**Goal:** Identify repeated failed Windows logins from the same source.  
**Event ID:** 4625  
**MITRE ATT&CK:** T1110 - Brute Force

```spl
index=windows EventCode=4625
| stats count min(_time) as first_seen max(_time) as last_seen by Account_Name, Source_Network_Address
| where count >= 5
| sort - count
```

A high number of failed logins from one source against one account can indicate password guessing. Analysts should validate whether the source is expected and check for a successful login afterward.
