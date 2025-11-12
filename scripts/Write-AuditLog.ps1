# Write-AuditLog.ps1
# Centralized logging function for all audit scripts

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Verbose', 'Success')]
        [string]$Level = 'Info',

        [Parameter(Mandatory=$false)]
        [string]$LogPath = $null,

        [Parameter(Mandatory=$false)]
        [switch]$NoConsole,

        [Parameter(Mandatory=$false)]
        [switch]$NoFile,

        [Parameter(Mandatory=$false)]
        [string]$Source = $null
    )

    # Determine log path
    if (-not $LogPath) {
        if ($env:LOG_PATH) {
            $LogPath = $env:LOG_PATH
        } else {
            $LogPath = Join-Path -Path $PSScriptRoot -ChildPath "..\logs"
        }
    }

    # Ensure log directory exists
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Force -Path $LogPath | Out-Null
    }

    # Generate log filename based on script name if source not provided
    if (-not $Source) {
        $Source = if ($MyInvocation.ScriptName) {
            [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName)
        } else {
            "PowerShell"
        }
    }

    $logFileName = "$Source-$(Get-Date -Format 'yyyyMMdd').log"
    $logFile = Join-Path -Path $LogPath -ChildPath $logFileName

    # Create timestamp
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'

    # Format log entry
    $logEntry = "$timestamp [$Level] [$Source] $Message"

    # Write to console if not suppressed
    if (-not $NoConsole) {
        switch ($Level) {
            'Error' {
                Write-Host $logEntry -ForegroundColor Red
            }
            'Warning' {
                Write-Host $logEntry -ForegroundColor Yellow
            }
            'Success' {
                Write-Host $logEntry -ForegroundColor Green
            }
            'Debug' {
                if ($VerbosePreference -eq 'Continue' -or $DebugPreference -eq 'Continue') {
                    Write-Host $logEntry -ForegroundColor Gray
                }
            }
            'Verbose' {
                if ($VerbosePreference -eq 'Continue') {
                    Write-Host $logEntry -ForegroundColor Cyan
                }
            }
            default {
                Write-Host $logEntry -ForegroundColor White
            }
        }
    }

    # Write to file if not suppressed
    if (-not $NoFile) {
        try {
            Add-Content -Path $logFile -Value $logEntry -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write to log file: $_"
        }
    }

    # Also write to Windows Event Log if running with appropriate permissions
    try {
        if ($Level -in @('Error', 'Warning') -and (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\AuditScripts" -ErrorAction SilentlyContinue)) {
            $eventType = switch ($Level) {
                'Error' { 'Error' }
                'Warning' { 'Warning' }
                default { 'Information' }
            }

            Write-EventLog -LogName Application -Source "AuditScripts" -EventId 1000 -EntryType $eventType -Message $Message -ErrorAction SilentlyContinue
        }
    } catch {
        # Silently continue if unable to write to Event Log
    }
}

function Initialize-AuditLogging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ScriptName = $null,

        [Parameter(Mandatory=$false)]
        [string]$LogPath = $null,

        [Parameter(Mandatory=$false)]
        [switch]$EnableTranscript
    )

    # Set up script name
    if (-not $ScriptName) {
        $ScriptName = if ($MyInvocation.ScriptName) {
            [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName)
        } else {
            "PowerShell"
        }
    }

    # Set up log path
    if (-not $LogPath) {
        if ($env:LOG_PATH) {
            $LogPath = $env:LOG_PATH
        } else {
            $LogPath = Join-Path -Path $PSScriptRoot -ChildPath "..\logs"
        }
    }

    # Ensure log directory exists
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Force -Path $LogPath | Out-Null
    }

    # Enable transcript if requested
    if ($EnableTranscript) {
        $transcriptPath = if ($env:TRANSCRIPT_PATH) {
            $env:TRANSCRIPT_PATH
        } else {
            Join-Path -Path $PSScriptRoot -ChildPath "..\transcripts"
        }

        if (-not (Test-Path $transcriptPath)) {
            New-Item -ItemType Directory -Force -Path $transcriptPath | Out-Null
        }

        $transcriptFile = Join-Path -Path $transcriptPath -ChildPath "$ScriptName-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

        try {
            Start-Transcript -Path $transcriptFile -Append -ErrorAction Stop
            Write-AuditLog -Message "Transcript started: $transcriptFile" -Level Info -Source $ScriptName
        } catch {
            Write-AuditLog -Message "Failed to start transcript: $_" -Level Warning -Source $ScriptName
        }
    }

    # Register event source if running with admin privileges
    try {
        if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            if (-not (Get-EventLog -LogName Application -Source "AuditScripts" -ErrorAction SilentlyContinue)) {
                New-EventLog -LogName Application -Source "AuditScripts" -ErrorAction SilentlyContinue
                Write-AuditLog -Message "Event log source 'AuditScripts' registered" -Level Info -Source $ScriptName
            }
        }
    } catch {
        # Silently continue if unable to register event source
    }

    Write-AuditLog -Message "Logging initialized for $ScriptName" -Level Info -Source $ScriptName
    Write-AuditLog -Message "Log path: $LogPath" -Level Debug -Source $ScriptName
}

function Stop-AuditLogging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ScriptName = $null
    )

    if (-not $ScriptName) {
        $ScriptName = if ($MyInvocation.ScriptName) {
            [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName)
        } else {
            "PowerShell"
        }
    }

    Write-AuditLog -Message "Logging stopped for $ScriptName" -Level Info -Source $ScriptName

    # Stop transcript if running
    try {
        $transcriptActive = $Host.UI.RawUI.WindowTitle -match "Transcript"
        if ($transcriptActive) {
            Stop-Transcript -ErrorAction SilentlyContinue
        }
    } catch {
        # Silently continue
    }
}

# Note: Export-ModuleMember is only for modules (.psm1 files)
# Since this is a .ps1 script that gets dot-sourced, functions are automatically available