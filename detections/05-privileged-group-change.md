# Detection 05 - Privileged Group Membership Change

**Goal:** Identify a user being added to a privileged local group.  
**Event ID:** 4732  
**MITRE ATT&CK:** T1098 - Account Manipulation

```spl
index=windows EventCode=4732
| table _time Computer SubjectUserName MemberName GroupName
| sort - _time
```

Unexpected membership changes to groups such as Administrators should be reviewed quickly because they may represent privilege escalation or persistence.
