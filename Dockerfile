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

# Run SysmonLikeAudit.ps1 to configure comprehensive auditing and logging
RUN powershell -Command ".\scripts\SysmonLikeAudit.ps1"

# Health check to verify Event Log service is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 `
    CMD powershell -Command "try { Get-Service EventLog | Where-Object {$_.Status -eq 'Running'} } catch { exit 1 }"

# Default command - keep container running and show logs
CMD ["powershell", "-NoExit", "-Command", "Write-Host 'Windows Audit Testing Container Ready'; Write-Host 'Event Log Service Status:'; Get-Service EventLog; Write-Host ''; Write-Host 'Run tests with: docker exec <container> powershell -File C:\\workspace\\scripts\\Test-EventIDGeneration.ps1'; Get-Content -Path 'C:\\Windows\\System32\\Winevt\\Logs\\Security.evtx' -Wait -ErrorAction SilentlyContinue"]
