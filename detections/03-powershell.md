# Detection 03 - Suspicious PowerShell

**Goal:** Identify PowerShell commands commonly associated with obfuscation or remote retrieval.  
**Event ID:** 4104  
**MITRE ATT&CK:** T1059.001 - PowerShell

```spl
index=windows EventCode=4104
| search ScriptBlockText="*EncodedCommand*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*DownloadString*"
| table _time Computer User ScriptBlockText
```

These terms are not automatically malicious. Analysts should evaluate the command, parent process, user context, host role, and surrounding events.
