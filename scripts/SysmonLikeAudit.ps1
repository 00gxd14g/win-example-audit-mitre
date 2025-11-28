<#
.SYNOPSIS
    Enables detailed Windows audit policies to provide Sysmon-like logging capabilities.

.DESCRIPTION
    This script configures Windows auditing to capture a wide range of security-relevant events.
    It enables detailed logging for object access (files, registry, kernel objects), process creation,
    network connections, and account management. Additionally, it configures advanced PowerShell
    logging (module, script block, and transcription) and sets the size and retention policy for
    key event logs to ensure events are not lost due to log rotation.

    The script performs the following actions:
    1. Sets audit policies for object access, detailed tracking, logon/logoff, and policy changes.
    2. Configures the system to include command-line arguments in process creation events.
    3. Enables advanced PowerShell logging features.
    4. Adjusts the maximum size and retention policy of the Security, System, and Application event logs.

.EXAMPLE
    PS C:\> .\SysmonLikeAudit.ps1
    This command executes the script, which will apply all the audit policy and logging changes.
    It must be run from an elevated PowerShell prompt (Run as Administrator).

.NOTES
    - This script must be run with Administrator privileges.
    - The execution policy for PowerShell scripts must be set to allow running local scripts.
      You can set this for the current process by running:
      Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
#>

# Requires -ExecutionPolicy Bypass

Write-Host "Enabling Sysmon-like audit policies..."

# Core Object Access subcategories
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable

# Detailed Tracking
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

# Logon/Logoff and Account Management
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Policy/State changes
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

# Include command line in process creation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# PowerShell advanced logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\pstranscripts" /f

# Event log size/retention
$maxSize = 33554432
$logs = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security",
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System",
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"
)
foreach ($log in $logs) {
    Set-ItemProperty -Path $log -Name "MaxSize" -Value $maxSize
    Set-ItemProperty -Path $log -Name "Retention" -Value 0
}

Write-Host "Done. Sysmon-like auditing enabled."
