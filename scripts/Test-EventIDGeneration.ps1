<#
.SYNOPSIS
    Tests whether Windows audit event IDs are properly configured and being generated.

.DESCRIPTION
    This script performs comprehensive testing of Windows audit configuration by:
    1. Checking current audit policy settings
    2. Verifying registry configurations for PowerShell and process logging
    3. Generating test events to trigger specific Event IDs
    4. Querying the Security, System, and PowerShell logs to verify events were created
    5. Providing a detailed report of audit coverage and missing configurations

.PARAMETER TestEventGeneration
    If specified, the script will actively generate test events to verify logging

.PARAMETER DetailedReport
    If specified, provides detailed output for each test performed

.PARAMETER ExportResults
    If specified, exports results to a JSON file for further analysis

.EXAMPLE
    PS C:\> .\Test-EventIDGeneration.ps1
    Checks audit policy configuration without generating test events

.EXAMPLE
    PS C:\> .\Test-EventIDGeneration.ps1 -TestEventGeneration -DetailedReport
    Performs comprehensive testing with event generation and detailed output

.EXAMPLE
    PS C:\> .\Test-EventIDGeneration.ps1 -TestEventGeneration -ExportResults
    Tests event generation and exports results to JSON file

.NOTES
    - This script must be run with Administrator privileges
    - Some test events may trigger security alerts if monitoring is in place
    - The script creates temporary files and registry keys for testing purposes
    - All test artifacts are cleaned up after testing
#>

[CmdletBinding()]
param(
    [switch]$TestEventGeneration,
    [switch]$DetailedReport,
    [switch]$ExportResults
)

#Requires -RunAsAdministrator

# Initialize results
$script:TestResults = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $env:COMPUTERNAME
    AuditPolicyTests = @{}
    RegistryTests = @{}
    EventGenerationTests = @{}
    Coverage = @{}
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Windows Event ID Generation Test Suite" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

#region Helper Functions

function Write-TestHeader {
    param([string]$Message)
    Write-Host "`n[TEST] $Message" -ForegroundColor Yellow
}

function Write-TestResult {
    param(
        [string]$Test,
        [bool]$Passed,
        [string]$Details = ""
    )

    $status = if ($Passed) {
        Write-Host "  [PASS]" -ForegroundColor Green -NoNewline
        "PASS"
    } else {
        Write-Host "  [FAIL]" -ForegroundColor Red -NoNewline
        "FAIL"
    }

    Write-Host " $Test" -NoNewline
    if ($Details -and $DetailedReport) {
        Write-Host " - $Details" -ForegroundColor Gray
    } else {
        Write-Host ""
    }

    return @{
        Test = $Test
        Status = $status
        Details = $Details
        Timestamp = Get-Date -Format "HH:mm:ss"
    }
}

function Get-AuditPolSubcategory {
    param([string]$Subcategory)

    $output = auditpol /get /subcategory:"$Subcategory" 2>&1

    if ($output -match "Success and Failure") {
        return "Success and Failure"
    } elseif ($output -match "Success") {
        return "Success"
    } elseif ($output -match "Failure") {
        return "Failure"
    } else {
        return "Not Configured"
    }
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue
    )

    try {
        $actualValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
        return $actualValue -eq $ExpectedValue
    } catch {
        return $false
    }
}

function Get-RecentEvents {
    param(
        [string]$LogName,
        [int[]]$EventIDs,
        [int]$Minutes = 5
    )

    $startTime = (Get-Date).AddMinutes(-$Minutes)

    try {
        $filter = @{
            LogName = $LogName
            ID = $EventIDs
            StartTime = $startTime
        }

        return Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    } catch {
        return $null
    }
}

#endregion

#region Audit Policy Tests

Write-TestHeader "Testing Audit Policy Configuration"

$auditCategories = @{
    "Logon" = @{Expected = "Success and Failure"; Critical = $true}
    "Process Creation" = @{Expected = "Success"; Critical = $true}
    "User Account Management" = @{Expected = "Success and Failure"; Critical = $true}
    "File System" = @{Expected = "Success and Failure"; Critical = $false}
    "Registry" = @{Expected = "Success and Failure"; Critical = $false}
    "Kernel Object" = @{Expected = "Success"; Critical = $false}
    "SAM" = @{Expected = "Success and Failure"; Critical = $true}
    "File Share" = @{Expected = "Success and Failure"; Critical = $true}
    "Detailed File Share" = @{Expected = "Success and Failure"; Critical = $true}
    "Audit Policy Change" = @{Expected = "Success and Failure"; Critical = $true}
    "Kerberos Authentication Service" = @{Expected = "Success and Failure"; Critical = $true}
    "Handle Manipulation" = @{Expected = "Success and Failure"; Critical = $false}
    "Security State Change" = @{Expected = "Success"; Critical = $false}
    "Other Object Access Events" = @{Expected = "Success"; Critical = $false}
    "Filtering Platform Connection" = @{Expected = "Success and Failure"; Critical = $false}
}

foreach ($category in $auditCategories.Keys) {
    $config = $auditCategories[$category]
    $currentSetting = Get-AuditPolSubcategory -Subcategory $category
    $passed = $currentSetting -like "*$($config.Expected)*" -or
              $currentSetting -eq "Success and Failure"

    $result = Write-TestResult -Test $category -Passed $passed -Details "Current: $currentSetting | Expected: $($config.Expected)"
    $script:TestResults.AuditPolicyTests[$category] = $result
}

#endregion

#region Registry Configuration Tests

Write-TestHeader "Testing Registry Configuration"

$registryTests = @{
    "Process Creation Command Line" = @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        Name = "ProcessCreationIncludeCmdLine_Enabled"
        ExpectedValue = 1
    }
    "PowerShell Module Logging" = @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        Name = "EnableModuleLogging"
        ExpectedValue = 1
    }
    "PowerShell Script Block Logging" = @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        Name = "EnableScriptBlockLogging"
        ExpectedValue = 1
    }
    "PowerShell Transcription" = @{
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        Name = "EnableTranscripting"
        ExpectedValue = 1
    }
}

foreach ($testName in $registryTests.Keys) {
    $test = $registryTests[$testName]
    $passed = Test-RegistryValue -Path $test.Path -Name $test.Name -ExpectedValue $test.ExpectedValue
    $result = Write-TestResult -Test $testName -Passed $passed -Details "$($test.Path)\$($test.Name)"
    $script:TestResults.RegistryTests[$testName] = $result
}

#endregion

#region Event Generation Tests

if ($TestEventGeneration) {
    Write-TestHeader "Generating Test Events"
    Write-Host "  This will create various activities to trigger Event IDs..." -ForegroundColor Gray

    # Array to track what events we're testing
    $eventTests = @()

    # Test 1: Process Creation (Event ID 4688)
    Write-Host "`n  [*] Testing Process Creation (Event ID 4688)..." -ForegroundColor Cyan
    $tempScript = "$env:TEMP\test_process_$((Get-Date).Ticks).bat"
    "@echo off`necho Test Process" | Out-File -FilePath $tempScript -Encoding ASCII
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $tempScript" -Wait -WindowStyle Hidden
    Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    $eventTests += @{EventID = 4688; LogName = "Security"; Description = "Process Creation"}

    # Test 2: Registry Modification (Event ID 4657)
    Write-Host "  [*] Testing Registry Modification (Event ID 4657)..." -ForegroundColor Cyan
    $testRegPath = "HKCU:\SOFTWARE\EventIDTest_$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -Path $testRegPath -Force | Out-Null
    Set-ItemProperty -Path $testRegPath -Name "TestValue" -Value "TestData"
    Remove-Item -Path $testRegPath -Force -ErrorAction SilentlyContinue
    $eventTests += @{EventID = 4657; LogName = "Security"; Description = "Registry Modification"}

    # Test 3: File Access (Event ID 4663)
    Write-Host "  [*] Testing File Access (Event ID 4663)..." -ForegroundColor Cyan
    $testFile = "$env:TEMP\test_file_$((Get-Date).Ticks).txt"
    "Test Content" | Out-File -FilePath $testFile
    Get-Content $testFile | Out-Null
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    $eventTests += @{EventID = 4663; LogName = "Security"; Description = "File Access"}

    # Test 4: PowerShell Script Block (Event ID 4104)
    Write-Host "  [*] Testing PowerShell Script Block Logging (Event ID 4104)..." -ForegroundColor Cyan
    $testCommand = "Write-Host 'EventID Test: PowerShell Script Block Logging'"
    Invoke-Expression $testCommand
    $eventTests += @{EventID = 4104; LogName = "Microsoft-Windows-PowerShell/Operational"; Description = "PowerShell Script Block"}

    # Test 5: PowerShell Module Logging (Event ID 4103)
    Write-Host "  [*] Testing PowerShell Module Logging (Event ID 4103)..." -ForegroundColor Cyan
    Get-Date | Out-Null
    $eventTests += @{EventID = 4103; LogName = "Microsoft-Windows-PowerShell/Operational"; Description = "PowerShell Module Logging"}

    # Test 6: Scheduled Task (Event ID 4698) - requires admin
    Write-Host "  [*] Testing Scheduled Task Creation (Event ID 4698)..." -ForegroundColor Cyan
    $taskName = "EventIDTest_$(Get-Date -Format 'yyyyMMddHHmmss')"
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo test"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(24)
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force | Out-Null
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $eventTests += @{EventID = 4698; LogName = "Security"; Description = "Scheduled Task Created"}
    } catch {
        Write-Host "    Warning: Could not create scheduled task (requires admin)" -ForegroundColor Yellow
    }

    # Wait for events to be written
    Write-Host "`n  Waiting for events to be written to logs..." -ForegroundColor Gray
    Start-Sleep -Seconds 3

    # Verify events were generated
    Write-TestHeader "Verifying Generated Events"

    foreach ($test in $eventTests) {
        $events = Get-RecentEvents -LogName $test.LogName -EventIDs @($test.EventID) -Minutes 2
        $passed = $null -ne $events -and $events.Count -gt 0
        $details = if ($passed) {
            "Found $($events.Count) event(s)"
        } else {
            "No events found in $($test.LogName)"
        }

        $result = Write-TestResult -Test "$($test.Description) (Event $($test.EventID))" -Passed $passed -Details $details
        $script:TestResults.EventGenerationTests["Event_$($test.EventID)"] = $result
    }
}

#endregion

#region Event Log Analysis

Write-TestHeader "Analyzing Recent Security Events"

$criticalEventIDs = @{
    4624 = "Successful Logon"
    4625 = "Failed Logon"
    4688 = "Process Creation"
    4698 = "Scheduled Task Created"
    4720 = "User Account Created"
    4768 = "Kerberos TGT Requested"
    4769 = "Kerberos Service Ticket"
    5140 = "Network Share Accessed"
    5156 = "Network Connection Allowed"
}

Write-Host "  Checking for recent critical events (last 24 hours)..." -ForegroundColor Gray

foreach ($eventID in $criticalEventIDs.Keys) {
    $events = Get-RecentEvents -LogName "Security" -EventIDs @($eventID) -Minutes 1440
    $count = if ($events) { $events.Count } else { 0 }

    if ($count -gt 0) {
        Write-Host "  [+] Event $eventID ($($criticalEventIDs[$eventID])): $count events" -ForegroundColor Green
    } else {
        Write-Host "  [-] Event $eventID ($($criticalEventIDs[$eventID])): No events found" -ForegroundColor Yellow
    }

    $script:TestResults.Coverage["Event_$eventID"] = @{
        EventID = $eventID
        Description = $criticalEventIDs[$eventID]
        Count = $count
        Present = $count -gt 0
    }
}

#endregion

#region Summary Report

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$auditPassed = ($script:TestResults.AuditPolicyTests.Values | Where-Object { $_.Status -eq "PASS" }).Count
$auditTotal = $script:TestResults.AuditPolicyTests.Count
$auditPercentage = [math]::Round(($auditPassed / $auditTotal) * 100, 2)

Write-Host "Audit Policy Tests: $auditPassed/$auditTotal passed ($auditPercentage%)" -ForegroundColor $(if ($auditPercentage -ge 80) { "Green" } elseif ($auditPercentage -ge 60) { "Yellow" } else { "Red" })

$regPassed = ($script:TestResults.RegistryTests.Values | Where-Object { $_.Status -eq "PASS" }).Count
$regTotal = $script:TestResults.RegistryTests.Count
$regPercentage = [math]::Round(($regPassed / $regTotal) * 100, 2)

Write-Host "Registry Tests: $regPassed/$regTotal passed ($regPercentage%)" -ForegroundColor $(if ($regPercentage -ge 80) { "Green" } elseif ($regPercentage -ge 60) { "Yellow" } else { "Red" })

if ($TestEventGeneration) {
    $eventPassed = ($script:TestResults.EventGenerationTests.Values | Where-Object { $_.Status -eq "PASS" }).Count
    $eventTotal = $script:TestResults.EventGenerationTests.Count
    $eventPercentage = if ($eventTotal -gt 0) { [math]::Round(($eventPassed / $eventTotal) * 100, 2) } else { 0 }

    Write-Host "Event Generation Tests: $eventPassed/$eventTotal passed ($eventPercentage%)" -ForegroundColor $(if ($eventPercentage -ge 80) { "Green" } elseif ($eventPercentage -ge 60) { "Yellow" } else { "Red" })
}

$coverageCount = ($script:TestResults.Coverage.Values | Where-Object { $_.Present }).Count
$coverageTotal = $script:TestResults.Coverage.Count
Write-Host "Event Coverage (24h): $coverageCount/$coverageTotal Event IDs have activity`n" -ForegroundColor Cyan

# Recommendations
Write-Host "Recommendations:" -ForegroundColor Yellow
$failedAudits = $script:TestResults.AuditPolicyTests.Values | Where-Object { $_.Status -eq "FAIL" }
if ($failedAudits.Count -gt 0) {
    Write-Host "  - Run SysmonLikeAudit.ps1 or win-audit.ps1 to configure missing audit policies" -ForegroundColor Yellow
}

$failedReg = $script:TestResults.RegistryTests.Values | Where-Object { $_.Status -eq "FAIL" }
if ($failedReg.Count -gt 0) {
    Write-Host "  - PowerShell logging is not fully configured. Run the audit scripts to enable." -ForegroundColor Yellow
}

if (-not $TestEventGeneration) {
    Write-Host "  - Run with -TestEventGeneration flag to verify events are being logged" -ForegroundColor Yellow
}

#endregion

#region Export Results

if ($ExportResults) {
    $outputFile = "EventID_Test_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $script:TestResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host "`n[*] Results exported to: $outputFile" -ForegroundColor Green
}

#endregion

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Testing Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Exit with appropriate code
$overallPassed = ($auditPercentage -ge 70) -and ($regPercentage -ge 70)
if ($overallPassed) {
    Write-Host "Overall Status: HEALTHY" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Overall Status: NEEDS ATTENTION" -ForegroundColor Red
    exit 1
}
