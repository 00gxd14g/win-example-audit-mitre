# Sysmon-like Windows Auditing Script

This script configures Windows to capture detailed audit events on processes, files, registry, network connections, and more, closely mirroring Sysmon functionality. It also sets PowerShell advanced logging and limits the Security, System, and Application event logs to 32MB with an overwrite policy.

## Features
- **Object Access** (File System, Registry, Kernel, SAM, etc.)  
- **Filtering Platform** (network events)  
- **Process Creation** with command line capture  
- **PowerShell** module, script block, and transcription logging  
- **Log size** set to 32MB with overwrite to prevent disk issues  

## Usage
1. Open PowerShell as Administrator.  
2. Run the script:
   ```powershell
   .\SysmonLikeAudit.ps1
