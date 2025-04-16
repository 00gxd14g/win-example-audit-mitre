# Enhanced Windows Auditing Script (Sysmon-like)

This PowerShell script enables advanced auditing settings similar to Sysmon. It captures events for process creation, file system, registry, and network connections. It also sets PowerShell module/script block logging and configures event log size and retention to avoid overwhelming the system.

## Features
- **Process Creation** (with command line)  
- **File System** and **Registry** auditing  
- **Filtering Platform Connection** for network auditing  
- **PowerShell Module and Script Block Logging**  
- **Event Log** size limit (32MB) and overwrite policy  

## Usage
1. Run PowerShell as Administrator.  
2. Save and run the script:  
   ```powershell
   .\EnhancedAudit.ps1
