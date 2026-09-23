# Detection 04 - New Local Account Creation

**Goal:** Detect creation of a new Windows user account.  
**Event ID:** 4720  
**MITRE ATT&CK:** T1136.001 - Local Account

```spl
index=windows EventCode=4720
| table _time Computer SubjectUserName TargetUserName
| sort - _time
```

Validate whether the account creation was authorized and review any later privilege changes.
