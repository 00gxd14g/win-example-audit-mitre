# MITRE ATT&CK to Windows Event ID Mapping

This document provides a comprehensive mapping between Windows Security Event IDs and MITRE ATT&CK framework tactics and techniques. Use this reference to understand which Event IDs to monitor for specific attack techniques.

## Table of Contents
- [Mapping Table by MITRE Tactic](#mapping-table-by-mitre-tactic)
- [Quick Reference: Event ID to MITRE Technique](#quick-reference-event-id-to-mitre-technique)
- [Detection Use Cases](#detection-use-cases)

---

## Mapping Table by MITRE Tactic

### TA0001 - Initial Access

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1078 | Valid Accounts | 4624, 4625, 4648, 4672 | Monitor for successful (4624) and failed (4625) logons, especially Type 3 (network) and Type 10 (RDP). Event 4648 indicates explicit credential usage. Event 4672 shows privilege escalation after logon. |
| T1133 | External Remote Services | 4624 (Type 10), 4778, 4779 | Track Remote Desktop (Type 10) logons and session reconnect/disconnect events |
| T1566 | Phishing | 4688, 4104, 5156 | Monitor process creation for suspicious Office/browser child processes, PowerShell downloads, and outbound connections |

### TA0002 - Execution

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1059.001 | PowerShell | 4688, 4103, 4104, 4105, 4106 | Event 4688 shows powershell.exe execution. Events 4103/4104 capture detailed script content, including obfuscated or encoded commands |
| T1059.003 | Windows Command Shell | 4688 | Monitor cmd.exe process creation, especially with suspicious parent processes or encoded/obfuscated arguments |
| T1053.005 | Scheduled Task/Job | 4698, 4699, 4700, 4701, 4702, 106 | Track scheduled task creation (4698), modification (4702), and execution. Task Scheduler operational log Event 106 shows task registration |
| T1047 | Windows Management Instrumentation | 4688, 4104 | Monitor for WMI process execution (wmic.exe, scrcons.exe) and PowerShell WMI cmdlets |
| T1203 | Exploitation for Client Execution | 4688, 4663 | Unusual process relationships (e.g., Office spawning cmd.exe/powershell.exe) |
| T1204 | User Execution | 4688, 4663 | Monitor execution from temp directories, downloads, or with suspicious file extensions |
| T1569.002 | Service Execution | 7045, 4697, 4688 | Monitor for new service installation (7045/4697) and execution of service binaries. |

### TA0003 - Persistence

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1053.005 | Scheduled Task/Job | 4698, 4699, 4702 | Monitor scheduled task creation and modification for persistence mechanisms |
| T1136 | Create Account | 4720, 4722, 4738 | Track local and domain account creation, especially accounts added to privileged groups |
| T1098 | Account Manipulation | 4738, 4732, 4733, 4756, 4757 | Monitor account property changes and group membership modifications |
| T1547.001 | Registry Run Keys | 4657, 4663, 4688 | Monitor registry modifications to Run/RunOnce keys and startup folder access |
| T1543.003 | Windows Service | 4697, 7045, 7036 | Track new service installations (4697, 7045 in System log) |
| T1546 | Event Triggered Execution | 4657, 4698, 4688 | Monitor WMI event subscriptions, AppInit DLLs, and accessibility feature modifications |
| T1574.001 | DLL Search Order Hijacking | 4688, 4663, 7045 | Unusual DLL loads or service installations |

### TA0004 - Privilege Escalation

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1068 | Exploitation for Privilege Escalation | 4688, 4672, 4673, 4674 | Monitor for unexpected privilege elevation (4672) and privileged service calls |
| T1134 | Access Token Manipulation | 4672, 4673, 4674, 4688 | Track processes with SeDebugPrivilege, SeImpersonatePrivilege, or unusual token operations |
| T1548.002 | Bypass User Account Control | 4688, 4656, 4657 | Monitor for UAC bypass indicators: consent.exe, unusual process integrity levels, registry modifications |
| T1078 | Valid Accounts | 4672, 4624 (Type 2), 4648 | Administrative logons with special privileges assigned |
| T1543.003 | Windows Service | 4697, 7045, 4688 | Services running with SYSTEM privileges |

### TA0005 - Defense Evasion

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1070.001 | Clear Windows Event Logs | 1102, 1100, 104 | Event 1102 indicates Security log was cleared. Events 1100 and 104 show Event Log service shutdown |
| T1070.004 | File Deletion | 4660, 4663 | Monitor deletion of critical files, especially in System32 or security tool directories |
| T1112 | Modify Registry | 4657, 4663, 4656 | Track registry modifications, especially to security/audit settings and antivirus exclusions |
| T1562.001 | Disable or Modify Tools | 4719, 4657, 4688 | Monitor audit policy changes (4719) and security software termination |
| T1562.002 | Disable Windows Event Logging | 4719, 1100, 1102 | Audit policy disabled or Event Log service stopped |
| T1055 | Process Injection | 4688, 4656, 4663, 10 (Sysmon) | Monitor for processes accessing other process memory, especially LSASS |
| T1218 | System Binary Proxy Execution | 4688 | Detect abuse of regsvr32, rundll32, mshta, certutil, etc. |
| T1036 | Masquerading | 4688, 4663 | Processes with names similar to legitimate Windows binaries running from unusual locations |
| T1027 | Obfuscated Files or Information | 4688, 4104, 4663 | PowerShell with encoded commands, execution from archives |
| T1202 | Indirect Command Execution | 4688 | Monitor for forfiles, pcalua, etc. executing commands |
| T1070.006 | Timestomp | 4663 | Monitor for file attribute changes (AccessMask 0x100 - FILE_WRITE_ATTRIBUTES) on sensitive files. |

### TA0006 - Credential Access

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1003.001 | LSASS Memory | 4656, 4663, 10 (Sysmon) | Monitor for process access to lsass.exe. Look for AccessMask 0x1010 (PROCESS_VM_READ) or 0x1410. |
| T1003.002 | Security Account Manager | 4656, 4663, 4661 | Access to SAM registry hive or SAM database files |
| T1003.003 | NTDS | 4662, 4663, 4656 | Monitor access to ntds.dit file and AD database operations |
| T1558.003 | Kerberoasting | 4769 | Multiple service ticket requests (4769) with RC4 encryption, especially for user accounts with SPNs |
| T1558.004 | AS-REP Roasting | 4768, 4771 | Failed Kerberos pre-authentication (4771) for accounts with "Do not require pre-auth" enabled |
| T1110 | Brute Force | 4625, 4776, 4771 | Multiple failed logon attempts in short timeframe |
| T1555 | Credentials from Password Stores | 5376, 5377, 4663 | Credential Manager backup/restore events, access to credential files |
| T1212 | Exploitation for Credential Access | 4688, 4656, 4663 | Unusual access patterns to credential stores |
| T1187 | Forced Authentication | 5140, 5145, 4648 | Unexpected network share access or authentication requests |

### TA0007 - Discovery

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1087 | Account Discovery | 4688, 4661, 4662 | Monitor execution of net user, net group, whoami, and SAM/AD enumeration |
| T1069 | Permission Groups Discovery | 4688, 4799 | Commands: net group, net localgroup, Get-ADGroup |
| T1082 | System Information Discovery | 4688 | Execution of systeminfo, hostname, ver, ipconfig, etc. |
| T1083 | File and Directory Discovery | 4688, 4663 | Commands like dir, tree, Get-ChildItem |
| T1135 | Network Share Discovery | 4688, 5140, 5145 | net view, net share commands and share enumeration |
| T1046 | Network Service Scanning | 4688, 5156, 5157 | Port scanning tools or unusual network connection patterns |
| T1018 | Remote System Discovery | 4688 | Commands: ping, net view, nltest, dsquery |
| T1518 | Software Discovery | 4688, 4663 | Registry queries or WMI queries for installed software |
| T1057 | Process Discovery | 4688 | Execution of tasklist, Get-Process, wmic process |
| T1049 | System Network Connections Discovery | 4688 | Commands: netstat, Get-NetTCPConnection |

### TA0008 - Lateral Movement

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1021.001 | Remote Desktop Protocol | 4624 (Type 10), 4778, 4779 | Monitor RDP logons, especially from unusual source IPs or accounts |
| T1021.002 | SMB/Windows Admin Shares | 4624 (Type 3), 4648, 5140, 5145 | Network logons combined with admin share access (C$, ADMIN$) |
| T1021.003 | DCOM | 4688, 4624 (Type 3) | Execution via DCOM, often shows as svchost.exe child processes |
| T1021.006 | Windows Remote Management | 4624 (Type 3), 4688 | WinRM connections (port 5985/5986) and wsmprovhost.exe execution |
| T1047 | Windows Management Instrumentation | 4688, 4624 (Type 3) | Remote WMI execution patterns |
| T1550.002 | Pass the Hash | 4624 (Type 3), 4648, 4776 | Network logon with NTLM authentication, no corresponding Kerberos events |
| T1550.003 | Pass the Ticket | 4624, 4768, 4769 | Unusual Kerberos ticket usage patterns, ticket requests from abnormal locations |
| T1570 | Lateral Tool Transfer | 5140, 5145, 4663 | File writes to admin shares or unusual executables accessed |

### TA0009 - Collection

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1005 | Data from Local System | 4663, 4656 | Access to sensitive file locations (Documents, Desktop, database files) |
| T1039 | Data from Network Shared Drive | 5140, 5145, 4663 | Enumeration and access to network shares |
| T1074 | Data Staged | 4663, 4656, 4658 | Creation of archives or large file operations in staging directories |
| T1114 | Email Collection | 4663, 4688 | Access to PST/OST files or email client process activity |
| T1056.001 | Keylogging | 4688, 4656, 4663 | Suspicious processes with keyboard/input access |
| T1113 | Screen Capture | 4688, 4663 | Execution of screenshot tools or GDI access patterns |
| T1125 | Video Capture | 4688, 4656 | Access to webcam devices or related APIs |

### TA0010 - Command and Control

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1071 | Application Layer Protocol | 5156, 5157, 4688 | Unusual outbound connections, especially from scripting engines |
| T1573 | Encrypted Channel | 5156 | Outbound connections to unusual ports or destinations |
| T1090 | Proxy | 5156, 4688 | Proxy tool execution or unusual connection patterns |
| T1219 | Remote Access Software | 4688, 5156, 4697 | Installation and execution of remote access tools |
| T1105 | Ingress Tool Transfer | 5156, 4663, 4688 | Downloads followed by execution |
| T1571 | Non-Standard Port | 5156, 5158 | Network connections on non-standard ports |

### TA0011 - Exfiltration

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1020 | Automated Exfiltration | 5156, 4663, 4688 | Scheduled tasks or scripts accessing files and initiating network connections |
| T1030 | Data Transfer Size Limits | 5156, 4663 | Patterns of repeated small file uploads |
| T1048 | Exfiltration Over Alternative Protocol | 5156, 5157 | Data transfers over DNS, ICMP, or other unusual protocols |
| T1041 | Exfiltration Over C2 Channel | 5156, 4688 | Large outbound data transfers from compromised systems |
| T1567 | Exfiltration Over Web Service | 5156, 4688, 4104 | Uploads to cloud storage services or file sharing sites |

### TA0040 - Impact

| Technique ID | Technique Name | Event IDs | Description |
|--------------|----------------|-----------|-------------|
| T1486 | Data Encrypted for Impact | 4663, 4656, 4660, 4688 | Mass file modifications, ransomware process indicators |
| T1489 | Service Stop | 4697, 7036, 7040 | Security services stopped or disabled |
| T1490 | Inhibit System Recovery | 4688, 4657 | Deletion of backups, shadow copies (vssadmin.exe, wbadmin.exe) |
| T1491 | Defacement | 4663, 4656 | Modification of web content or visible system files |
| T1485 | Data Destruction | 4660, 4663 | Mass file deletions |
| T1561 | Disk Wipe | 4688, 4663 | Execution of disk wiping tools or raw disk access |

---

## Quick Reference: Event ID to MITRE Technique

This table provides a reverse lookup from Event ID to associated MITRE ATT&CK techniques.

| Event ID | Event Description | Primary MITRE Techniques |
|----------|-------------------|--------------------------|
| 1100 | Event Log Service Shutdown | T1070.001, T1562.002 |
| 1102 | Security Log Cleared | T1070.001, T1562.002 |
| 4624 | Successful Logon | T1078 (all subtypes), T1021.001, T1021.002, T1550.002, T1550.003 |
| 4625 | Failed Logon | T1110 (Brute Force) |
| 4634 | Account Logoff | T1078 (logon tracking) |
| 4647 | User-Initiated Logoff | T1078 (session tracking) |
| 4648 | Logon with Explicit Credentials | T1078, T1021.002, T1550.002 |
| 4656 | Handle to Object Requested | T1003.001, T1003.002, T1055, T1005, T1074 |
| 4657 | Registry Value Modified | T1112, T1547.001, T1562.001 |
| 4660 | Object Deleted | T1070.004, T1485 |
| 4661 | SAM Object Access | T1003.002, T1087 |
| 4662 | AD Object Operation | T1003.003, T1087, T1069 |
| 4663 | Object Access Attempt | T1005, T1074, T1003.001, T1003.002, T1039, T1114 |
| 4672 | Special Privileges Assigned | T1078, T1068, T1134 |
| 4673 | Privileged Service Called | T1068, T1134 |
| 4674 | Privileged Object Operation | T1068, T1134 |
| 4688 | Process Created | Nearly all execution, discovery, and lateral movement techniques |
| 4697 | Service Installed | T1543.003, T1574.001, T1219 |
| 4698 | Scheduled Task Created | T1053.005, T1053.002 |
| 4699 | Scheduled Task Deleted | T1053.005 |
| 4700 | Scheduled Task Enabled | T1053.005 |
| 4701 | Scheduled Task Disabled | T1053.005, T1562.001 |
| 4702 | Scheduled Task Updated | T1053.005 |
| 4719 | Audit Policy Changed | T1562.001, T1562.002 |
| 4720 | User Account Created | T1136.001, T1136.002 |
| 4722 | User Account Enabled | T1098 |
| 4723 | Password Change Attempt | T1098 |
| 4724 | Password Reset Attempt | T1098 |
| 4725 | User Account Disabled | T1531 (Account Access Removal) |
| 4726 | User Account Deleted | T1531 |
| 4732 | User Added to Security Group | T1098, T1136 |
| 4733 | User Removed from Security Group | T1098 |
| 4738 | User Account Changed | T1098, T1136 |
| 4740 | User Account Locked | T1110, T1531 |
| 4756 | Member Added to Universal Security Group | T1098 |
| 4757 | Member Removed from Universal Security Group | T1098 |
| 4768 | Kerberos TGT Requested | T1558.001 (Golden Ticket), T1550.003 |
| 4769 | Kerberos Service Ticket Requested | T1558.003 (Kerberoasting), T1558.002 (Silver Ticket) |
| 4771 | Kerberos Pre-auth Failed | T1558.004 (AS-REP Roasting), T1110 |
| 4776 | Credential Validation | T1110, T1550.002 (Pass the Hash) |
| 4778 | RDP Session Reconnected | T1021.001 |
| 4779 | RDP Session Disconnected | T1021.001 |
| 4799 | Security-Enabled Group Enumerated | T1069 |
| 5136 | Directory Service Object Modified | T1098 |
| 5137 | Directory Service Object Created | T1136 |
| 5140 | Network Share Accessed | T1021.002, T1039, T1570 |
| 5145 | Detailed File Share Access | T1021.002, T1039, T1570 |
| 5156 | Network Connection Allowed | T1071, T1573, T1105, T1041, T1048 |
| 5157 | Network Connection Blocked | T1071 (blocked attempts) |
| 5158 | Port Bind | T1571, T1219 |
| 5376 | Credential Manager Backup | T1555.003 |
| 5377 | Credential Manager Restore | T1555.003 |
| 7045 | Service Installed (System Log) | T1543.003, T1574.001 |
| 4103 | PowerShell Module Logging | T1059.001 |
| 4104 | PowerShell Script Block | T1059.001, T1027, T1105, T1071 |

---

## Detection Use Cases

### Use Case 1: Credential Dumping (LSASS Memory)

**MITRE Technique**: T1003.001

**Detection Logic**:
```
Event 4656 OR 4663
WHERE TargetObject CONTAINS "lsass.exe"
AND AccessMask CONTAINS "0x1010" (PROCESS_VM_READ)
AND ProcessName NOT IN (known_security_tools)
```

**Relevant Event IDs**: 4656, 4663

---

### Use Case 2: Kerberoasting

**MITRE Technique**: T1558.003

**Detection Logic**:
```
Event 4769
WHERE ServiceName ENDS WITH "$" = FALSE
AND TicketEncryptionType = "0x17" (RC4)
AND ServiceName NOT IN (known_service_accounts)
GROUP BY Account
HAVING COUNT > 10 within 10 minutes
```

**Relevant Event IDs**: 4769

---

### Use Case 3: Pass-the-Hash

**MITRE Technique**: T1550.002

**Detection Logic**:
```
Event 4624
WHERE LogonType = 3
AND AuthenticationPackage = "NTLM"
AND NOT EXISTS (Event 4768 OR 4769 for same LogonGUID within 1 minute)
AND SourceNetworkAddress NOT IN (known_service_ips)
```

**Relevant Event IDs**: 4624, 4776, absence of 4768/4769

---

### Use Case 4: Golden Ticket

**MITRE Technique**: T1558.001

**Detection Logic**:
```
Event 4768
WHERE (TicketLifetime > 10 hours OR TicketEncryptionType = "0x17")
AND Account NOT IN (known_service_accounts)
```

**Relevant Event IDs**: 4768, 4769, 4624

---

### Use Case 5: Lateral Movement via RDP

**MITRE Technique**: T1021.001

**Detection Logic**:
```
Event 4624
WHERE LogonType = 10
AND SourceNetworkAddress NOT IN (known_admin_workstations)
FOLLOWED BY Event 4688 within 5 minutes
WHERE ProcessName CONTAINS suspicious_tool
```

**Relevant Event IDs**: 4624, 4778, 4779, 4688

---

### Use Case 6: Scheduled Task Persistence

**MITRE Technique**: T1053.005

**Detection Logic**:
```
Event 4698
WHERE TaskContent CONTAINS (powershell OR cmd OR script OR suspicious_path)
AND Creator NOT IN (SYSTEM, known_admin_accounts)
```

**Relevant Event IDs**: 4698, 4702, 4699

---

### Use Case 7: Defense Evasion - Log Clearing

**MITRE Technique**: T1070.001

**Detection Logic**:
```
Event 1102
CORRELATED WITH Event 4688 (wevtutil OR Clear-EventLog)
```

**Relevant Event IDs**: 1102, 1100, 104

---

### Use Case 8: PowerShell Obfuscation

**MITRE Technique**: T1027, T1059.001

**Detection Logic**:
```
Event 4104
WHERE ScriptBlockText CONTAINS (
    "FromBase64String" OR
    "-enc" OR
    "Invoke-Expression" OR
    "IEX" OR
    "DownloadString" OR
    "WebClient"
)
```

**Relevant Event IDs**: 4104, 4103, 4688

---

### Use Case 9: Account Creation and Privilege Escalation

**MITRE Technique**: T1136, T1098

**Detection Logic**:
```
Event 4720 (Account Created)
FOLLOWED BY Event 4732 (Added to Administrators group) within 30 minutes
WHERE Creator NOT IN (known_admin_accounts)
```

**Relevant Event IDs**: 4720, 4732, 4738

---

### Use Case 10: Discovery - Network Reconnaissance

**MITRE Technique**: T1018, T1046, T1135

**Detection Logic**:
```
Event 4688
WHERE ProcessName IN ("net.exe", "nltest.exe", "dsquery.exe", "nmap.exe")
OR CommandLine CONTAINS ("net view", "net group", "nltest /dclist")
GROUP BY SourceHost
HAVING COUNT > 5 within 5 minutes
```

**Relevant Event IDs**: 4688

---

## MITRE ATT&CK Coverage Analysis

### Event Coverage by Tactic

| Tactic | Coverage | Key Event IDs |
|--------|----------|---------------|
| Initial Access | High | 4624, 4625, 4648, 4778 |
| Execution | High | 4688, 4103, 4104, 4698 |
| Persistence | High | 4698, 4720, 4697, 4657 |
| Privilege Escalation | High | 4672, 4673, 4688 |
| Defense Evasion | Medium | 4719, 1102, 4657, 4688 |
| Credential Access | High | 4656, 4663, 4768, 4769, 4776 |
| Discovery | High | 4688, 4661, 4662 |
| Lateral Movement | High | 4624, 4648, 5140, 5145 |
| Collection | Medium | 4663, 4656 |
| Command & Control | Medium | 5156, 5157, 4688 |
| Exfiltration | Medium | 5156, 4663 |
| Impact | Medium | 4663, 4660, 4688 |

### Techniques NOT Well-Covered by Windows Event Logs

Some MITRE ATT&CK techniques require additional telemetry sources beyond Windows Event Logs:

- **T1195** - Supply Chain Compromise (requires code signing, vulnerability scanning)
- **T1190** - Exploit Public-Facing Application (requires IIS/web server logs)
- **T1059.004** - Unix Shell (requires EDR on Linux systems)
- **T1566.001** - Spearphishing Attachment (requires email gateway logs)
- **Network Traffic Analysis** - Requires network monitoring tools (Zeek, Suricata)
- **File Integrity** - Requires FIM solutions for comprehensive coverage
- **Memory Analysis** - Requires EDR or Sysmon Event ID 10

**Recommendation**: Combine Windows Event Log monitoring with:
- Sysmon for enhanced process, network, and file activity
- EDR solutions for memory and behavioral analysis
- Network monitoring for C2 communications
- Email gateway logs for phishing detection

---

## Related Documentation

- [EVENT_IDS.md](EVENT_IDS.md) - Comprehensive Event ID reference
- [readme.md](readme.md) - Project overview and usage instructions

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Windows Security Auditing](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/)
- [NSA Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance)
- [JPCERT Windows Event Log Analysis](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [Ultimate Windows Security Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

---

**Version**: 1.0
**Last Updated**: 2025-11-11
