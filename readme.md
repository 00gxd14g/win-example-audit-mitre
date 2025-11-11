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
