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

# Note: We do NOT set auditpol at image build time to avoid localization
# and platform differences causing non-zero exit codes. Audit policies are
# configured at runtime by scripts/win-audit.ps1 and scripts/SysmonLikeAudit.ps1.

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
