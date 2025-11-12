<#
.SYNOPSIS
    Runs comprehensive audit testing in Docker container environment

.DESCRIPTION
    This script orchestrates all testing operations for Windows Event Log auditing
    in a Docker container. It validates audit configurations, generates test events,
    verifies event logging, and produces detailed test reports.

.PARAMETER TestSuite
    Specifies which test suite to run:
    - All: Run all tests (default)
    - AuditConfig: Only test audit policy configuration
    - EventGeneration: Only test event generation
    - Synthetic: Generate synthetic attack logs
    - Integration: Full end-to-end integration tests

.PARAMETER OutputFormat
    Output format for test results: JSON, CSV, XML, or Console (default: JSON)

.PARAMETER ExportPath
    Path to export test results (default: C:\test-results)

.PARAMETER Verbose
    Enable verbose output for detailed test information

.EXAMPLE
    .\Run-DockerTests.ps1 -TestSuite All -Verbose
    Runs all tests with verbose output

.EXAMPLE
    .\Run-DockerTests.ps1 -TestSuite EventGeneration -OutputFormat JSON
    Runs only event generation tests and exports to JSON

.NOTES
    Author: Windows Audit Testing Framework
    Version: 1.0.0
    Requires: PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('All', 'AuditConfig', 'EventGeneration', 'Synthetic', 'Integration')]
    [string]$TestSuite = 'All',

    [Parameter(Mandatory=$false)]
    [ValidateSet('JSON', 'CSV', 'XML', 'Console')]
    [string]$OutputFormat = 'JSON',

    [Parameter(Mandatory=$false)]
    [string]$ExportPath = 'C:\test-results',

    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = 'Continue'
$OriginalVerbosePreference = $VerbosePreference
if ($Verbose) {
    $VerbosePreference = 'Continue'
}

# Script configuration
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceRoot = Split-Path -Parent $ScriptRoot
$TestStartTime = Get-Date

# Test results collection
$TestResults = @{
    TestSuite = $TestSuite
    StartTime = $TestStartTime
    Environment = @{
        Hostname = $env:COMPUTERNAME
        OSVersion = [System.Environment]::OSVersion.VersionString
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsContainer = (Test-Path 'C:\.containerenv' -ErrorAction SilentlyContinue)
        IsAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    Tests = @()
    Summary = @{
        Total = 0
        Passed = 0
        Failed = 0
        Skipped = 0
    }
}

# Helper functions
function Write-TestHeader {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = '',
        [object]$Details = $null
    )

    $result = @{
        TestName = $TestName
        Passed = $Passed
        Message = $Message
        Details = $Details
        Timestamp = Get-Date
    }

    $TestResults.Tests += $result
    $TestResults.Summary.Total++

    if ($Passed) {
        $TestResults.Summary.Passed++
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
    } else {
        $TestResults.Summary.Failed++
        Write-Host "  [FAIL] $TestName" -ForegroundColor Red
    }

    if ($Message) {
        Write-Host "         $Message" -ForegroundColor Gray
    }
}

function Test-AuditConfiguration {
    Write-TestHeader "Audit Configuration Tests"

    # Test 1: Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-TestResult -TestName "Administrator Privileges Check" -Passed $isAdmin -Message "Running with $(if($isAdmin){'Administrator'}else{'User'}) privileges"

    # Test 2: Event Log service status
    try {
        $eventLogService = Get-Service -Name EventLog -ErrorAction Stop
        $servicePassed = $eventLogService.Status -eq 'Running'
        Write-TestResult -TestName "Event Log Service Status" -Passed $servicePassed -Message "Service status: $($eventLogService.Status)"
    } catch {
        Write-TestResult -TestName "Event Log Service Status" -Passed $false -Message "Error: $_"
    }

    # Test 3: Audit policy categories
    $categories = @(
        'Object Access',
        'Logon/Logoff',
        'Process Tracking',
        'Account Management',
        'Policy Change',
        'Privilege Use',
        'System'
    )

    foreach ($category in $categories) {
        try {
            $auditOutput = auditpol /get /category:"$category" 2>&1
            $hasSuccess = $auditOutput -match 'Success'
            Write-TestResult -TestName "Audit Policy: $category" -Passed $hasSuccess -Message $(if($hasSuccess){"Enabled"}else{"Not configured"})
        } catch {
            Write-TestResult -TestName "Audit Policy: $category" -Passed $false -Message "Error checking policy"
        }
    }

    # Test 4: Registry configurations
    $registryTests = @(
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            Name = 'ProcessCreationIncludeCmdLine_Enabled'
            ExpectedValue = 1
            Description = 'Process Command Line Logging'
        },
        @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
            Name = 'EnableModuleLogging'
            ExpectedValue = 1
            Description = 'PowerShell Module Logging'
        },
        @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            Name = 'EnableScriptBlockLogging'
            ExpectedValue = 1
            Description = 'PowerShell Script Block Logging'
        },
        @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            Name = 'EnableTranscripting'
            ExpectedValue = 1
            Description = 'PowerShell Transcription'
        }
    )

    foreach ($test in $registryTests) {
        try {
            if (Test-Path $test.Path) {
                $value = Get-ItemProperty -Path $test.Path -Name $test.Name -ErrorAction Stop
                $actualValue = $value.$($test.Name)
                $passed = $actualValue -eq $test.ExpectedValue
                Write-TestResult -TestName "Registry: $($test.Description)" -Passed $passed -Message "Value: $actualValue (Expected: $($test.ExpectedValue))"
            } else {
                Write-TestResult -TestName "Registry: $($test.Description)" -Passed $false -Message "Registry path not found"
            }
        } catch {
            Write-TestResult -TestName "Registry: $($test.Description)" -Passed $false -Message "Error reading registry: $_"
        }
    }
}

function Test-EventGeneration {
    Write-TestHeader "Event Generation Tests"

    # Run the existing Test-EventIDGeneration.ps1 script
    $testScript = Join-Path $ScriptRoot 'Test-EventIDGeneration.ps1'

    if (Test-Path $testScript) {
        try {
            Write-Host "  Running Test-EventIDGeneration.ps1..." -ForegroundColor Yellow
            $result = & $testScript -TestEventGeneration -DetailedReport -ExportResults -ExportPath $ExportPath
            Write-TestResult -TestName "Event Generation Script Execution" -Passed $true -Message "Script executed successfully"
        } catch {
            Write-TestResult -TestName "Event Generation Script Execution" -Passed $false -Message "Error: $_"
        }
    } else {
        Write-TestResult -TestName "Event Generation Script Execution" -Passed $false -Message "Test-EventIDGeneration.ps1 not found"
    }
}

function Test-SyntheticLogs {
    Write-TestHeader "Synthetic Log Generation Tests"

    # Run the Generate-SyntheticLogs.ps1 script
    $syntheticScript = Join-Path $ScriptRoot 'Generate-SyntheticLogs.ps1'

    if (Test-Path $syntheticScript) {
        $scenarios = @('CredentialDumping', 'LateralMovement', 'PrivilegeEscalation')

        foreach ($scenario in $scenarios) {
            try {
                Write-Host "  Generating synthetic logs for: $scenario..." -ForegroundColor Yellow
                $outputPath = Join-Path $ExportPath "synthetic-$scenario"
                & $syntheticScript -Scenario $scenario -EventCount 20 -OutputPath $outputPath -ExportFormat JSON

                # Verify output was created
                $passed = Test-Path $outputPath
                Write-TestResult -TestName "Synthetic Logs: $scenario" -Passed $passed -Message $(if($passed){"Generated at $outputPath"}else{"Output not created"})
            } catch {
                Write-TestResult -TestName "Synthetic Logs: $scenario" -Passed $false -Message "Error: $_"
            }
        }
    } else {
        Write-TestResult -TestName "Synthetic Log Generation" -Passed $false -Message "Generate-SyntheticLogs.ps1 not found"
    }
}

function Test-Integration {
    Write-TestHeader "Integration Tests"

    # Test 1: Apply audit configuration and verify
    $auditScript = Join-Path $ScriptRoot 'win-audit.ps1'
    if (Test-Path $auditScript) {
        try {
            Write-Host "  Applying audit configuration..." -ForegroundColor Yellow
            & $auditScript
            Start-Sleep -Seconds 2

            # Verify configuration was applied
            $auditOutput = auditpol /get /category:* 2>&1
            $passed = $auditOutput -match 'Success'
            Write-TestResult -TestName "Apply Audit Configuration" -Passed $passed -Message "Configuration applied"
        } catch {
            Write-TestResult -TestName "Apply Audit Configuration" -Passed $false -Message "Error: $_"
        }
    }

    # Test 2: Generate test event and verify it appears in Event Log
    try {
        Write-Host "  Generating test process event..." -ForegroundColor Yellow
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo test" -Wait -WindowStyle Hidden
        Start-Sleep -Seconds 2

        # Query for recent 4688 events
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4688
        } -MaxEvents 10 -ErrorAction Stop

        $passed = $events.Count -gt 0
        Write-TestResult -TestName "End-to-End Event Logging" -Passed $passed -Message "Found $($events.Count) process creation events"
    } catch {
        Write-TestResult -TestName "End-to-End Event Logging" -Passed $false -Message "Error querying events: $_"
    }

    # Test 3: Verify PowerShell logging
    try {
        Write-Host "  Testing PowerShell logging..." -ForegroundColor Yellow
        Invoke-Expression "Get-Process | Select-Object -First 1"
        Start-Sleep -Seconds 2

        $psEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'
            ID = 4104
        } -MaxEvents 5 -ErrorAction Stop

        $passed = $psEvents.Count -gt 0
        Write-TestResult -TestName "PowerShell Script Block Logging" -Passed $passed -Message "Found $($psEvents.Count) script block events"
    } catch {
        Write-TestResult -TestName "PowerShell Script Block Logging" -Passed $false -Message "No PowerShell events found or error: $_"
    }
}

# Main execution logic
try {
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Windows Audit Docker Test Suite          ║" -ForegroundColor Cyan
    Write-Host "║  Test Suite: $($TestSuite.PadRight(28)) ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan

    # Create export path if it doesn't exist
    if (-not (Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }

    # Run selected test suites
    switch ($TestSuite) {
        'All' {
            Test-AuditConfiguration
            Test-EventGeneration
            Test-SyntheticLogs
            Test-Integration
        }
        'AuditConfig' {
            Test-AuditConfiguration
        }
        'EventGeneration' {
            Test-EventGeneration
        }
        'Synthetic' {
            Test-SyntheticLogs
        }
        'Integration' {
            Test-Integration
        }
    }

    # Calculate execution time
    $TestResults.EndTime = Get-Date
    $TestResults.Duration = ($TestResults.EndTime - $TestStartTime).TotalSeconds

    # Display summary
    Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  Test Summary                              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "  Total Tests:   $($TestResults.Summary.Total)" -ForegroundColor White
    Write-Host "  Passed:        $($TestResults.Summary.Passed)" -ForegroundColor Green
    Write-Host "  Failed:        $($TestResults.Summary.Failed)" -ForegroundColor $(if($TestResults.Summary.Failed -gt 0){'Red'}else{'Green'})
    Write-Host "  Duration:      $([math]::Round($TestResults.Duration, 2)) seconds" -ForegroundColor White
    Write-Host ""

    # Export results
    if ($OutputFormat -ne 'Console') {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $outputFile = Join-Path $ExportPath "test-results-$timestamp.$($OutputFormat.ToLower())"

        switch ($OutputFormat) {
            'JSON' {
                $TestResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
            }
            'CSV' {
                $TestResults.Tests | Export-Csv -Path $outputFile -NoTypeInformation
            }
            'XML' {
                $TestResults | Export-Clixml -Path $outputFile
            }
        }

        Write-Host "Results exported to: $outputFile" -ForegroundColor Green
    }

    # Set exit code based on test results
    $exitCode = if ($TestResults.Summary.Failed -gt 0) { 1 } else { 0 }
    exit $exitCode

} catch {
    Write-Host "`nFATAL ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
} finally {
    $VerbosePreference = $OriginalVerbosePreference
}
