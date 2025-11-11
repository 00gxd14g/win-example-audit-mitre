# Windows Event IDs Reference

This document provides a comprehensive reference for all Windows Event IDs that can be logged when using the auditing scripts in this repository.

## Table of Contents
- [SysmonLikeAudit.ps1 Event IDs](#sysmonlikeauditps1-event-ids)
- [win-audit.ps1 Event IDs](#win-auditps1-event-ids)
- [PowerShell Logging Event IDs](#powershell-logging-event-ids)
- [Event ID Reference by Category](#event-id-reference-by-category)

---

## SysmonLikeAudit.ps1 Event IDs

The `SysmonLikeAudit.ps1` script enables comprehensive auditing that generates the following Event IDs:

### Object Access Events

#### File System (4656, 4658, 4660, 4663, 4664, 4985, 5051, 5140, 5142, 5143, 5144, 5145)
- **4656** - A handle to an object was requested
- **4658** - The handle to an object was closed
- **4660** - An object was deleted
- **4663** - An attempt was made to access an object (file/folder)
- **4664** - An attempt was made to create a hard link
- **4985** - The state of a transaction has changed
- **5051** - A file was virtualized
- **5140** - A network share object was accessed
- **5142** - A network share object was added
- **5143** - A network share object was modified
- **5144** - A network share object was deleted
- **5145** - A network share object was checked to see whether client can be granted desired access

#### Registry (4656, 4657, 4658, 4660, 4663, 5039, 5040)
- **4656** - A handle to an object was requested (registry key)
- **4657** - A registry value was modified
- **4658** - The handle to an object was closed (registry key)
- **4660** - An object was deleted (registry key)
- **4663** - An attempt was made to access an object (registry key)
- **5039** - A registry key was virtualized
- **5040** - A change has been made to IPsec (stored in registry)

#### Kernel Object (4656, 4658, 4660, 4663)
- **4656** - A handle to an object was requested (kernel object)
- **4658** - The handle to an object was closed (kernel object)
- **4660** - An object was deleted (kernel object)
- **4663** - An attempt was made to access an object (kernel object)

#### SAM (4661, 4662)
- **4661** - A handle to an object was requested (SAM)
- **4662** - An operation was performed on an object (SAM/Active Directory)

#### Handle Manipulation (4690, 4658, 4656)
- **4656** - A handle to an object was requested
- **4658** - The handle to an object was closed
- **4690** - An attempt was made to duplicate a handle to an object

#### Other Object Access Events (4691, 4698, 4699, 4700, 4701, 4702, 5888, 5889, 5890)
- **4691** - Indirect access to an object was requested
- **4698** - A scheduled task was created
- **4699** - A scheduled task was deleted
- **4700** - A scheduled task was enabled
- **4701** - A scheduled task was disabled
- **4702** - A scheduled task was updated
- **5888** - An object in the COM+ Catalog was modified
- **5889** - An object was deleted from the COM+ Catalog
- **5890** - An object was added to the COM+ Catalog

#### File Share (5140, 5142, 5143, 5144)
- **5140** - A network share object was accessed
- **5142** - A network share object was added
- **5143** - A network share object was modified
- **5144** - A network share object was deleted

#### Detailed File Share (5145, 5140)
- **5140** - A network share object was accessed
- **5145** - A network share object was checked to see whether client can be granted desired access

#### Filtering Platform Connection (5031, 5150, 5151, 5154, 5155, 5156, 5157, 5158, 5159)
- **5031** - The Windows Firewall Service blocked an application from accepting incoming connections
- **5150** - The Windows Filtering Platform blocked a packet
- **5151** - A more restrictive Windows Filtering Platform filter has blocked a packet
- **5154** - The Windows Filtering Platform has permitted an application to listen on a port
- **5155** - The Windows Filtering Platform has blocked an application from listening on a port
- **5156** - The Windows Filtering Platform has permitted a connection
- **5157** - The Windows Filtering Platform has blocked a connection
- **5158** - The Windows Filtering Platform has permitted a bind to a local port
- **5159** - The Windows Filtering Platform has blocked a bind to a local port

#### Filtering Platform Packet Drop (5152, 5153)
- **5152** - The Windows Filtering Platform blocked a packet
- **5153** - A more restrictive Windows Filtering Platform filter has blocked a packet

#### IPsec Driver (4960, 4961, 4962, 4963, 4964, 4965, 5040, 5041, 5042, 5043, 5044, 5045, 5046, 5047, 5048)
- **4960** - IPsec dropped an inbound packet that failed an integrity check
- **4961** - IPsec dropped an inbound packet that failed a replay check
- **4962** - IPsec dropped an inbound packet that failed validation
- **4963** - IPsec dropped an inbound clear text packet that should have been secured
- **4964** - Special groups have been assigned to a new logon
- **4965** - IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI)
- **5040** - A change has been made to IPsec settings
- **5041** - A change has been made to IPsec settings
- **5042** - A change has been made to IPsec settings
- **5043** - A change has been made to IPsec settings
- **5044** - A change has been made to IPsec settings
- **5045** - A change has been made to IPsec settings
- **5046** - A change has been made to IPsec settings
- **5047** - A change has been made to IPsec settings
- **5048** - A change has been made to IPsec settings

### Process Tracking Events

#### Process Creation (4688, 4689)
- **4688** - A new process has been created (includes command line when configured)
- **4689** - A process has exited

### Logon/Logoff Events

#### Logon (4624, 4625, 4634, 4647, 4648, 4672, 4675, 4776, 4964, 4649)
- **4624** - An account was successfully logged on
- **4625** - An account failed to log on
- **4634** - An account was logged off
- **4647** - User initiated logoff
- **4648** - A logon was attempted using explicit credentials
- **4672** - Special privileges assigned to new logon
- **4675** - SIDs were filtered
- **4776** - The computer attempted to validate the credentials for an account (NTLM)
- **4964** - Special groups have been assigned to a new logon
- **4649** - A replay attack was detected

### Account Management Events

#### User Account Management (4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781, 4794, 5376, 5377)
- **4720** - A user account was created
- **4722** - A user account was enabled
- **4723** - An attempt was made to change an account's password
- **4724** - An attempt was made to reset an account's password
- **4725** - A user account was disabled
- **4726** - A user account was deleted
- **4738** - A user account was changed
- **4740** - A user account was locked out
- **4765** - SID History was added to an account
- **4766** - An attempt to add SID History to an account failed
- **4767** - A user account was unlocked
- **4780** - The ACL was set on accounts which are members of administrators groups
- **4781** - The name of an account was changed
- **4794** - An attempt was made to set the Directory Services Restore Mode administrator password
- **5376** - Credential Manager credentials were backed up
- **5377** - Credential Manager credentials were restored from a backup

#### Kerberos Authentication Service (4768, 4769, 4770, 4771, 4772, 4773)
- **4768** - A Kerberos authentication ticket (TGT) was requested
- **4769** - A Kerberos service ticket was requested
- **4770** - A Kerberos service ticket was renewed
- **4771** - Kerberos pre-authentication failed
- **4772** - A Kerberos authentication ticket request failed
- **4773** - A Kerberos service ticket request failed

### Policy Change Events

#### Audit Policy Change (4715, 4719, 4817, 4902, 4904, 4905, 4906, 4907, 4908, 4912)
- **4715** - The audit policy (SACL) on an object was changed
- **4719** - System audit policy was changed
- **4817** - Auditing settings on object were changed
- **4902** - The Per-user audit policy table was created
- **4904** - An attempt was made to register a security event source
- **4905** - An attempt was made to unregister a security event source
- **4906** - The CrashOnAuditFail value has changed
- **4907** - Auditing settings on object were changed
- **4908** - Special Groups Logon table modified
- **4912** - Per User Audit Policy was changed

#### Security State Change (4608, 4609, 4616, 4621, 5038, 5056, 5057, 5058, 5059, 5060, 5061, 5062)
- **4608** - Windows is starting up
- **4609** - Windows is shutting down
- **4616** - The system time was changed
- **4621** - Administrator recovered system from CrashOnAuditFail
- **5038** - Code integrity determined that the image hash of a file is not valid
- **5056** - A cryptographic self-test was performed
- **5057** - A cryptographic primitive operation failed
- **5058** - Key file operation
- **5059** - Key migration operation
- **5060** - Verification operation failed
- **5061** - Cryptographic operation
- **5062** - A kernel-mode cryptographic self-test was performed

---

## win-audit.ps1 Event IDs

The `win-audit.ps1` script is MITRE ATT&CK-guided and generates the following Event IDs (with some subcategories limited to success-only to reduce false positives):

### Logon Events (4624, 4625, 4634, 4647, 4648, 4672, 4675, 4776)
- **4624** - An account was successfully logged on
- **4625** - An account failed to log on
- **4634** - An account was logged off
- **4647** - User initiated logoff
- **4648** - A logon was attempted using explicit credentials
- **4672** - Special privileges assigned to new logon
- **4675** - SIDs were filtered
- **4776** - The computer attempted to validate the credentials for an account

### Directory Service Changes (5136, 5137, 5138, 5139, 5141)
- **5136** - A directory service object was modified
- **5137** - A directory service object was created
- **5138** - A directory service object was undeleted
- **5139** - A directory service object was moved
- **5141** - A directory service object was deleted

### Process Creation (4688) - Success Only
- **4688** - A new process has been created (includes command line)
  - *Note: Failure logging disabled to reduce noise*

### User Account Management (4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766, 4767, 4780, 4781)
- **4720** - A user account was created
- **4722** - A user account was enabled
- **4723** - An attempt was made to change an account's password
- **4724** - An attempt was made to reset an account's password
- **4725** - A user account was disabled
- **4726** - A user account was deleted
- **4738** - A user account was changed
- **4740** - A user account was locked out
- **4765** - SID History was added to an account
- **4766** - An attempt to add SID History to an account failed
- **4767** - A user account was unlocked
- **4780** - The ACL was set on accounts which are members of administrators groups
- **4781** - The name of an account was changed

### Directory Service Access (4662)
- **4662** - An operation was performed on an object (Active Directory)

### SAM (4661, 4662)
- **4661** - A handle to an object was requested (SAM)
- **4662** - An operation was performed on an object (SAM)

### Detailed File Share (5145)
- **5145** - A network share object was checked to see whether client can be granted desired access

### File Share (5140, 5142, 5143, 5144)
- **5140** - A network share object was accessed
- **5142** - A network share object was added
- **5143** - A network share object was modified
- **5144** - A network share object was deleted

### Audit Policy Change (4715, 4719, 4817, 4902, 4904, 4905, 4906, 4907, 4908, 4912)
- **4715** - The audit policy (SACL) on an object was changed
- **4719** - System audit policy was changed
- **4817** - Auditing settings on object were changed
- **4902** - The Per-user audit policy table was created
- **4904** - An attempt was made to register a security event source
- **4905** - An attempt was made to unregister a security event source
- **4906** - The CrashOnAuditFail value has changed
- **4907** - Auditing settings on object were changed
- **4908** - Special Groups Logon table modified
- **4912** - Per User Audit Policy was changed

### Kerberos Authentication Service (4768, 4769, 4770, 4771, 4772, 4773)
- **4768** - A Kerberos authentication ticket (TGT) was requested
- **4769** - A Kerberos service ticket was requested
- **4770** - A Kerberos service ticket was renewed
- **4771** - Kerberos pre-authentication failed
- **4772** - A Kerberos authentication ticket request failed
- **4773** - A Kerberos service ticket request failed

### Kernel Object (4656, 4658, 4660, 4663) - Success Only
- **4656** - A handle to an object was requested (kernel object)
- **4658** - The handle to an object was closed (kernel object)
- **4660** - An object was deleted (kernel object)
- **4663** - An attempt was made to access an object (kernel object)
  - *Note: Failure logging disabled to reduce false positives*

### Other Object Access Events (4691, 4698, 4699, 4700, 4701, 4702) - Success Only
- **4691** - Indirect access to an object was requested
- **4698** - A scheduled task was created
- **4699** - A scheduled task was deleted
- **4700** - A scheduled task was enabled
- **4701** - A scheduled task was disabled
- **4702** - A scheduled task was updated
  - *Note: Failure logging disabled to reduce false positives*

### Handle Manipulation (4690, 4658, 4656)
- **4656** - A handle to an object was requested
- **4658** - The handle to an object was closed
- **4690** - An attempt was made to duplicate a handle to an object

### Security State Change (4608, 4616) - Success Only
- **4608** - Windows is starting up
- **4616** - The system time was changed
  - *Note: Failure logging disabled to reduce noise*

---

## PowerShell Logging Event IDs

Both scripts enable advanced PowerShell logging, which generates the following Event IDs in the **Microsoft-Windows-PowerShell/Operational** and **Windows PowerShell** logs:

### PowerShell Module Logging
- **4103** - Module logging (captures pipeline execution details)

### PowerShell Script Block Logging
- **4104** - Script block logging (captures PowerShell script execution)
- **4105** - Script block logging (start of script block)
- **4106** - Script block logging (end of script block)

### PowerShell Transcription
- Transcripts are written to `C:\pstranscripts\` directory as text files
- **4097** - PowerShell console starting up (if applicable)
- **4098** - PowerShell console ending (if applicable)

### PowerShell Engine Events
- **400** - Engine state changed to Available
- **403** - Engine state changed to Stopped
- **600** - Provider lifecycle events
- **800** - Pipeline execution details

---

## Event ID Reference by Category

### Critical Security Events to Monitor

#### Lateral Movement Detection
- **4648** - Explicit credential usage (Pass-the-Hash, Pass-the-Ticket)
- **4624** (Type 3) - Network logon
- **4624** (Type 10) - Remote Desktop logon
- **4768** - Kerberos TGT request
- **4769** - Kerberos service ticket (look for encryption downgrade, unusual services)
- **5140** - Network share access
- **5145** - Detailed share access

#### Privilege Escalation
- **4672** - Special privileges assigned to new logon (Administrator rights)
- **4673** - A privileged service was called
- **4674** - An operation was attempted on a privileged object
- **4688** - Process creation (watch for elevated processes)
- **4697** - A service was installed in the system

#### Persistence Mechanisms
- **4698** - Scheduled task created
- **4699** - Scheduled task deleted
- **4700** - Scheduled task enabled
- **4701** - Scheduled task disabled
- **4702** - Scheduled task updated
- **4720** - User account created
- **4722** - User account enabled
- **4738** - User account changed (especially privilege changes)

#### Credential Access
- **4624** (Type 9) - NewCredentials logon (RunAs)
- **4625** - Failed logon (brute force attempts)
- **4648** - Explicit credential usage
- **4768** - Kerberos TGT request (Golden Ticket detection)
- **4769** - Kerberos service ticket (Silver Ticket, Kerberoasting)
- **4771** - Kerberos pre-auth failed (AS-REP Roasting)
- **4776** - NTLM authentication (credential harvesting)
- **5376** - Credential Manager backup
- **5377** - Credential Manager restore

#### Defense Evasion
- **4657** - Registry value modification (disable security tools)
- **4663** - File access (deletion of logs)
- **4688** - Process creation (look for obfuscated commands)
- **4104** - PowerShell script blocks (obfuscated scripts, base64 encoded commands)
- **4719** - System audit policy changed (disabling logging)
- **5038** - Code integrity check failure (unsigned drivers/executables)

#### Discovery Activities
- **4688** - Process creation (reconnaissance commands: net, ipconfig, whoami, nltest)
- **4661** - SAM database enumeration
- **4662** - Active Directory object access
- **5136** - Directory service object modified
- **5137** - Directory service object created

#### Command and Control
- **5156** - Windows Filtering Platform permitted connection (outbound C2)
- **5157** - Windows Filtering Platform blocked connection
- **5158** - Bind to local port (backdoor listeners)
- **4688** - Process creation (suspicious network tools)
- **4104** - PowerShell script blocks (C2 beacon scripts)

#### Exfiltration
- **5140** - Network share accessed
- **5145** - Detailed file share access
- **5156** - Outbound connections to unusual destinations
- **4663** - Large file access patterns
- **4688** - Process creation (compression/archival tools)

### Logon Types Reference

When monitoring Event ID 4624 (successful logon), the logon type indicates the method:

- **Type 2** - Interactive (local keyboard/screen logon)
- **Type 3** - Network (accessing shared folders, IPC$)
- **Type 4** - Batch (scheduled tasks)
- **Type 5** - Service (service startup)
- **Type 7** - Unlock (workstation unlock)
- **Type 8** - NetworkCleartext (IIS basic auth)
- **Type 9** - NewCredentials (RunAs with /netonly)
- **Type 10** - RemoteInteractive (RDP, Terminal Services)
- **Type 11** - CachedInteractive (cached domain credentials)
- **Type 12** - CachedRemoteInteractive (cached RDP)
- **Type 13** - CachedUnlock (cached credentials unlock)

### Special SIDs in Event 4672 (Special Privileges)

The following Security Identifiers (SIDs) indicate high-privilege access:

- **SeDebugPrivilege** - Debug programs (can access any process memory)
- **SeBackupPrivilege** - Back up files and directories (can read any file)
- **SeRestorePrivilege** - Restore files and directories (can write any file)
- **SeTakeOwnershipPrivilege** - Take ownership of files/objects
- **SeLoadDriverPrivilege** - Load and unload device drivers
- **SeSecurityPrivilege** - Manage auditing and security log
- **SeSystemEnvironmentPrivilege** - Modify firmware environment variables
- **SeImpersonatePrivilege** - Impersonate a client after authentication
- **SeAssignPrimaryTokenPrivilege** - Replace process-level token
- **SeTcbPrivilege** - Act as part of the operating system

---

## Log Locations

Events are logged to the following Windows Event Log channels:

- **Security** - Most audit events (4xxx, 5xxx series)
- **System** - System-level events, some security state changes
- **Application** - Application-specific events
- **Microsoft-Windows-PowerShell/Operational** - PowerShell operational events (4103, 4104)
- **Windows PowerShell** - PowerShell engine events (400, 403, 600, 800)
- **Microsoft-Windows-TaskScheduler/Operational** - Detailed scheduled task events
- **Microsoft-Windows-Sysmon/Operational** - Sysmon events (if Sysmon is installed)

---

## Analysis Tips

### High-Priority Event Combinations for Threat Detection

1. **Lateral Movement Pattern**:
   - 4648 (explicit creds) + 4624 Type 3 (network logon) + 5140/5145 (share access)

2. **Privilege Escalation Pattern**:
   - 4688 (process creation) + 4672 (special privileges) + unusual parent-child process relationship

3. **Credential Dumping Pattern**:
   - 4688 (lsass.exe access) + 4656/4663 (LSASS process handle request)
   - Multiple 4776 events (NTLM auth) in short timespan

4. **Golden/Silver Ticket Usage**:
   - 4768 (TGT request) with unusual encryption type or long ticket lifetime
   - 4769 (service ticket) with unusual account name or service

5. **Kerberoasting**:
   - Multiple 4769 events requesting service tickets for SPNs with RC4 encryption

6. **Pass-the-Hash**:
   - 4624 Type 3 (network logon) + 4648 with NTLM auth, no 4768/4769

7. **PowerShell Attack**:
   - 4688 (powershell.exe) + 4104 with suspicious keywords (Invoke-Expression, DownloadString, encoded commands)

8. **Scheduled Task Persistence**:
   - 4698 (task created) + 4702 (task modified) + review task command line in 4688

9. **Account Manipulation**:
   - 4720 (account created) + 4732 (user added to privileged group) + 4738 (account changed)

10. **Defense Evasion**:
    - 4719 (audit policy changed to disable logging)
    - 4657 (registry modification of security software)
    - 1102 (security log cleared)

### Baseline Normal Activity

Before hunting for threats, establish baselines for:
- Normal logon patterns (4624) by user, time, and source
- Typical process creation (4688) hierarchies
- Regular scheduled tasks (4698)
- Standard network connections (5156)
- Routine PowerShell usage (4104)

### Query Optimization

When querying large Security logs:
1. Filter by Event ID first
2. Then filter by time window
3. Finally apply content filters (usernames, IPs, process names)

Example using PowerShell:
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
    StartTime=(Get-Date).AddHours(-24)
} | Where-Object {$_.Message -like "*powershell*"}
```

---

## Differences Between Scripts

### SysmonLikeAudit.ps1
- **Comprehensive**: Logs both success and failure for most categories
- **Higher volume**: More verbose logging, suitable for environments where storage is not a constraint
- **Network focus**: Includes extensive network filtering platform events
- **Best for**: Detailed forensic analysis, incident response, environments where detection accuracy is prioritized over log volume

### win-audit.ps1
- **MITRE ATT&CK aligned**: Focuses on techniques from the MITRE framework
- **Optimized**: Success-only logging for noisy categories (Process Creation, Kernel Object, Other Object Access, Security State Change)
- **Lower volume**: Reduces false positives and log storage requirements
- **Directory Services**: Includes Active Directory-specific auditing
- **Best for**: Environments with limited log storage, MITRE ATT&CK-based detection strategies, reducing analyst fatigue from false positives

---

## Additional Resources

- [Microsoft Security Auditing Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Event Log Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [NSA Cybersecurity Advisory on Event Logging](https://media.defense.gov/2023/Sep/27/2003304443/-1/-1/0/CTR_LOGGING_MADE_EASY.PDF)

---

## Version History

- **v1.0** - Initial documentation of Event IDs for both audit scripts
