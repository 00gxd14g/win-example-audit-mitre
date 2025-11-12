# escape=`
# Windows Server Core base image for testing Windows Event Log auditing
FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Set PowerShell as the default shell
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# Configure PowerShell execution policy
RUN Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

# Enable Windows Event Log service and ensure it's running
RUN Set-Service -Name EventLog -StartupType Automatic; `
    Start-Service -Name EventLog

# Create working directories
RUN New-Item -ItemType Directory -Force -Path C:\workspace; `
    New-Item -ItemType Directory -Force -Path C:\logs; `
    New-Item -ItemType Directory -Force -Path C:\test-results; `
    New-Item -ItemType Directory -Force -Path C:\pstranscripts

# Set the working directory
WORKDIR C:\workspace

# Copy all scripts and documentation
COPY scripts/ C:\workspace\scripts\
COPY docs/ C:\workspace\docs\
COPY tests/ C:\workspace\tests\

# Install chocolatey (optional, for additional tools)
RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Configure Event Log sizes to prevent overflow during testing
RUN wevtutil sl Security /ms:67108864; `
    wevtutil sl System /ms:67108864; `
    wevtutil sl Application /ms:67108864; `
    wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:67108864

# Enable advanced audit policies using subcategories (more reliable than categories)
# Object Access subcategories
RUN auditpol /set /subcategory:"File System" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable; `
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:disable; `
    auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable

# Logon/Logoff subcategories
RUN auditpol /set /subcategory:"Logon" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Logoff" /success:enable /failure:disable; `
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable; `
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

# Process Tracking subcategories
RUN auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable; `
    auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable

# Account Management subcategories
RUN auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable

# Policy Change subcategories
RUN auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable

# Privilege Use subcategories
RUN auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:disable; `
    auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable /failure:disable

# System subcategories
RUN auditpol /set /subcategory:"Security State Change" /success:enable /failure:disable; `
    auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable; `
    auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Other System Events" /success:enable /failure:disable

# Additional important subcategories for MITRE ATT&CK coverage
RUN auditpol /set /subcategory:"SAM" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable; `
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Enable process command line logging
RUN reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Enable PowerShell Module Logging
RUN reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f; `
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f

# Enable PowerShell Script Block Logging
RUN reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Enable PowerShell Transcription
RUN reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f; `
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\pstranscripts" /f; `
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f

# Health check to verify Event Log service is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 `
    CMD powershell -Command "try { Get-Service EventLog | Where-Object {$_.Status -eq 'Running'} } catch { exit 1 }"

# Default command - keep container running and show logs
CMD ["powershell", "-NoExit", "-Command", "Write-Host 'Windows Audit Testing Container Ready'; Write-Host 'Event Log Service Status:'; Get-Service EventLog; Write-Host ''; Write-Host 'Run tests with: docker exec <container> powershell -File C:\\workspace\\scripts\\Test-EventIDGeneration.ps1'; Get-Content -Path 'C:\\Windows\\System32\\Winevt\\Logs\\Security.evtx' -Wait -ErrorAction SilentlyContinue"]
