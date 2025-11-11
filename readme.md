# Windows Auditing Scripts

This repository contains PowerShell scripts designed to enhance Windows security auditing. These scripts configure Windows to capture detailed audit events, providing logging capabilities similar to what you would get from a tool like Sysmon.

## Scripts

There are two scripts in this repository:

1.  **`SysmonLikeAudit.ps1`**: This is the primary script, recommended for most users. It enables a comprehensive set of audit policies to log detailed information about:
    *   **Object Access**: File system, registry, kernel objects, SAM, and more.
    *   **Process Creation**: Includes the full command line for each process.
    *   **Network Events**: Filtering Platform connections and packet drops.
    *   **PowerShell**: Advanced logging for modules, script blocks, and transcripts.
    *   **Log Settings**: Sets the Security, System, and Application event logs to 32MB each, with a policy to overwrite old events as needed.

2.  **`win-audit.ps1`**: This script is similar to `SysmonLikeAudit.ps1` but is guided by MITRE ATT&CK. It also includes comments in Turkish. It's a good alternative if you are looking for a configuration that is more closely aligned with the MITRE framework.

## Usage

To use these scripts, you must have Administrator privileges.

1.  Open PowerShell as **Administrator**.
2.  You may need to adjust the PowerShell execution policy to allow the script to run. You can do this for the current session by running:

    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
    ```

3.  Navigate to the directory where you have saved the script and run it. For example, to run the main script, you would use:

    ```powershell
    .\SysmonLikeAudit.ps1
    ```

    To run the MITRE ATT&CK guided script:

    ```powershell
    .\win-audit.ps1
    ```

## Which Script Should I Use?

*   For a general, comprehensive audit policy that provides a lot of detail, use **`SysmonLikeAudit.ps1`**.
*   If you are working within the MITRE ATT&CK framework and want a script that aligns with its recommendations, use **`win-audit.ps1`**.

Both scripts provide a significant increase in the level of detail in your Windows event logs, which can be invaluable for security monitoring and incident response.

## Logged Event IDs

These scripts enable logging for a wide variety of security events. Here are some of the key Event IDs that you can expect to see in the Windows Event Log after running these scripts. This is not an exhaustive list, but it covers the most important events.

### Object Access

*   **File System (Event ID 4663):** An attempt was made to access an object. This event is generated when a file or folder is accessed, and it includes the name of the object, the user who accessed it, and the type of access that was requested.
*   **Registry (Event ID 4657):** A registry value was modified. This event is generated when a registry key or value is created, modified, or deleted.
*   **Kernel Object (Event ID 4660):** An object was deleted. This event is generated when a kernel object, such as a process or a thread, is deleted.
*   **SAM (Event ID 4704):** A user account was changed. This event is generated when a user account is created, modified, or deleted in the Security Account Manager (SAM).
*   **File Share (Event ID 5140):** A network share object was accessed. This event is generated when a user connects to a shared folder.
*   **Detailed File Share (Event ID 5145):** A network share object was checked for access. This event provides more detailed information than Event ID 5140, including the specific access rights that were requested.
*   **Filtering Platform Connection (Event ID 5156):** The Windows Filtering Platform has permitted a connection. This event is generated when a network connection is allowed by the Windows Firewall.
*   **Filtering Platform Packet Drop (Event ID 5157):** The Windows Filtering Platform has blocked a packet. This event is generated when a network packet is dropped by the Windows Firewall.

### Detailed Tracking

*   **Process Creation (Event ID 4688):** A new process has been created. This event is one of the most important for security monitoring, as it provides the name of the new process, the user who created it, and the command line that was used to start it.

### Logon/Logoff and Account Management

*   **Logon (Event ID 4624):** An account was successfully logged on. This event is generated when a user successfully logs on to a computer.
*   **User Account Management (Event ID 4720):** A user account was created. This event is generated when a new user account is created.
*   **Kerberos Authentication Service (Event ID 4768):** A Kerberos authentication ticket (TGT) was requested. This event is generated when a user attempts to authenticate to a domain controller.

### Policy/State Changes

*   **Audit Policy Change (Event ID 4719):** System audit policy was changed. This event is generated when the audit policy is modified.
*   **Security State Change (Event ID 4616):** The system time was changed. This event is generated when the system clock is changed.

### PowerShell Logging

In addition to the standard Windows Event Logs, these scripts also enable advanced PowerShell logging, which generates the following events:

*   **PowerShell Module Logging (Event ID 4103):** Module logging is enabled for all modules. This provides detailed information about the execution of PowerShell cmdlets.
*   **PowerShell Script Block Logging (Event ID 4104):** Script block logging is enabled. This logs the content of script blocks as they are executed, which can be very useful for detecting malicious PowerShell activity.
*   **PowerShell Transcription (Event ID 4105 & 4106):** PowerShell transcription is enabled. This creates a transcript of all PowerShell sessions, which is saved to `C:\pstranscripts`.
