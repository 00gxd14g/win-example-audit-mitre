# Test-AuditScripts-Local.ps1
# Bu scripti lokal Windows makinenizde admin yetkisi ile çalıştırın

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$ApplyChanges,
    [switch]$RevertChanges
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Windows Audit Scripts - Local Test Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check if running as admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Running with Administrator privileges" -ForegroundColor Green

# Backup current settings
function Backup-AuditSettings {
    Write-Host "`nBacking up current audit settings..." -ForegroundColor Yellow

    $backup = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        AuditPolicy = auditpol /backup /file:$env:TEMP\audit_backup.csv
        PowerShellLogging = @{}
        EventLogSizes = @{}
    }

    # Backup PowerShell logging settings
    $psKeys = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    )

    foreach ($key in $psKeys) {
        if (Test-Path $key) {
            $backup.PowerShellLogging[$key] = Get-ItemProperty -Path $key
        }
    }

    # Backup Event Log sizes
    $logs = @("Security", "System", "Application")
    foreach ($log in $logs) {
        $logInfo = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
        if ($logInfo) {
            $backup.EventLogSizes[$log] = $logInfo.MaximumSizeInBytes
        }
    }

    $backup | Export-Clixml -Path "$env:TEMP\audit_settings_backup_$($backup.Timestamp).xml"
    Write-Host "✓ Backup saved to: $env:TEMP\audit_settings_backup_$($backup.Timestamp).xml" -ForegroundColor Green

    return $backup
}

# Test win-audit.ps1
function Test-WinAudit {
    Write-Host "`n[TEST] Testing win-audit.ps1..." -ForegroundColor Yellow

    $scriptPath = Join-Path $PSScriptRoot "win-audit.ps1"

    if (-not (Test-Path $scriptPath)) {
        Write-Host "  ✗ Script not found: $scriptPath" -ForegroundColor Red
        return $false
    }

    if ($ApplyChanges) {
        Write-Host "  Applying audit policies..." -ForegroundColor Cyan
        try {
            & $scriptPath
            Write-Host "  ✓ win-audit.ps1 executed successfully" -ForegroundColor Green

            # Verify changes
            Write-Host "  Verifying changes..." -ForegroundColor Yellow

            # Check if Process Creation audit is enabled
            $processAudit = auditpol /get /subcategory:"Process Creation" 2>$null
            if ($processAudit -match "Success") {
                Write-Host "    ✓ Process Creation auditing enabled" -ForegroundColor Green
            } else {
                Write-Host "    ✗ Process Creation auditing not enabled" -ForegroundColor Red
            }

            # Check PowerShell logging
            if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging") {
                $sbLogging = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
                if ($sbLogging.EnableScriptBlockLogging -eq 1) {
                    Write-Host "    ✓ PowerShell Script Block Logging enabled" -ForegroundColor Green
                } else {
                    Write-Host "    ✗ PowerShell Script Block Logging not enabled" -ForegroundColor Red
                }
            }

            return $true
        } catch {
            Write-Host "  ✗ Error executing win-audit.ps1: $_" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "  Dry run mode - no changes will be made" -ForegroundColor Yellow
        Write-Host "  Use -ApplyChanges to actually modify audit settings" -ForegroundColor Yellow
        return $true
    }
}

# Test SysmonLikeAudit.ps1
function Test-SysmonLikeAudit {
    Write-Host "`n[TEST] Testing SysmonLikeAudit.ps1..." -ForegroundColor Yellow

    $scriptPath = Join-Path $PSScriptRoot "SysmonLikeAudit.ps1"

    if (-not (Test-Path $scriptPath)) {
        Write-Host "  ✗ Script not found: $scriptPath" -ForegroundColor Red
        return $false
    }

    if ($ApplyChanges) {
        Write-Host "  Applying Sysmon-like audit policies..." -ForegroundColor Cyan
        try {
            & $scriptPath
            Write-Host "  ✓ SysmonLikeAudit.ps1 executed successfully" -ForegroundColor Green

            # Verify Sysmon-like categories
            $categories = @(
                "File System",
                "Registry",
                "Handle Manipulation",
                "Kernel Object"
            )

            foreach ($cat in $categories) {
                $catAudit = auditpol /get /subcategory:"$cat" 2>$null
                if ($catAudit -match "Success|Failure") {
                    Write-Host "    ✓ $cat auditing enabled" -ForegroundColor Green
                } else {
                    Write-Host "    ✗ $cat auditing not enabled" -ForegroundColor Red
                }
            }

            return $true
        } catch {
            Write-Host "  ✗ Error executing SysmonLikeAudit.ps1: $_" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "  Dry run mode - no changes will be made" -ForegroundColor Yellow
        return $true
    }
}

# Test Test-EventIDGeneration.ps1
function Test-EventIDGeneration {
    Write-Host "`n[TEST] Testing Test-EventIDGeneration.ps1..." -ForegroundColor Yellow

    $scriptPath = Join-Path $PSScriptRoot "Test-EventIDGeneration.ps1"

    if (-not (Test-Path $scriptPath)) {
        Write-Host "  ✗ Script not found: $scriptPath" -ForegroundColor Red
        return $false
    }

    try {
        # Run the test script
        $result = & $scriptPath -DetailedReport
        Write-Host "  ✓ Test-EventIDGeneration.ps1 executed successfully" -ForegroundColor Green

        # If we applied changes, also test with event generation
        if ($ApplyChanges) {
            Write-Host "  Running with event generation..." -ForegroundColor Cyan
            & $scriptPath -TestEventGeneration
            Write-Host "  ✓ Event generation test completed" -ForegroundColor Green
        }

        return $true
    } catch {
        Write-Host "  ✗ Error executing Test-EventIDGeneration.ps1: $_" -ForegroundColor Red
        return $false
    }
}

# Test Generate-SyntheticLogs.ps1
function Test-GenerateSyntheticLogs {
    Write-Host "`n[TEST] Testing Generate-SyntheticLogs.ps1..." -ForegroundColor Yellow

    $scriptPath = Join-Path $PSScriptRoot "Generate-SyntheticLogs.ps1"

    if (-not (Test-Path $scriptPath)) {
        Write-Host "  ✗ Script not found: $scriptPath" -ForegroundColor Red
        return $false
    }

    try {
        # Test with minimal parameters
        & $scriptPath -EventCount 5 -OutputPath $env:TEMP\SyntheticLogs
        Write-Host "  ✓ Generate-SyntheticLogs.ps1 executed successfully" -ForegroundColor Green

        # Check if output was created
        if (Test-Path "$env:TEMP\SyntheticLogs") {
            $files = Get-ChildItem "$env:TEMP\SyntheticLogs" -Filter "*.json"
            Write-Host "  ✓ Generated $($files.Count) synthetic log files" -ForegroundColor Green
        }

        return $true
    } catch {
        Write-Host "  ✗ Error executing Generate-SyntheticLogs.ps1: $_" -ForegroundColor Red
        return $false
    }
}

# Revert changes
function Restore-AuditSettings {
    param($BackupFile)

    Write-Host "`nRestoring audit settings from backup..." -ForegroundColor Yellow

    if (-not (Test-Path $BackupFile)) {
        Write-Host "  ✗ Backup file not found: $BackupFile" -ForegroundColor Red
        return
    }

    try {
        # Restore audit policy
        auditpol /restore /file:$env:TEMP\audit_backup.csv
        Write-Host "  ✓ Audit policy restored" -ForegroundColor Green

        # Note: PowerShell logging and Event Log sizes would need manual restoration
        Write-Host "  ⚠ PowerShell logging settings need manual restoration" -ForegroundColor Yellow

    } catch {
        Write-Host "  ✗ Error restoring settings: $_" -ForegroundColor Red
    }
}

# Main execution
Write-Host "`nTest Mode: $(if($ApplyChanges){'APPLY CHANGES'}else{'DRY RUN'})" -ForegroundColor $(if($ApplyChanges){'Red'}else{'Yellow'})

if ($ApplyChanges) {
    Write-Host "⚠️  WARNING: This will modify your system audit settings!" -ForegroundColor Red
    Write-Host "Press Ctrl+C to cancel, or any key to continue..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    # Backup current settings
    $backup = Backup-AuditSettings
}

# Run tests
$results = @{
    "win-audit.ps1" = Test-WinAudit
    "SysmonLikeAudit.ps1" = Test-SysmonLikeAudit
    "Test-EventIDGeneration.ps1" = Test-EventIDGeneration
    "Generate-SyntheticLogs.ps1" = Test-GenerateSyntheticLogs
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$passed = 0
$failed = 0

foreach ($script in $results.Keys) {
    if ($results[$script]) {
        Write-Host "  ✓ $script - PASSED" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "  ✗ $script - FAILED" -ForegroundColor Red
        $failed++
    }
}

Write-Host "`nResults: $passed passed, $failed failed" -ForegroundColor $(if($failed -eq 0){'Green'}else{'Yellow'})

if ($RevertChanges -and $ApplyChanges) {
    Write-Host "`nReverting changes..." -ForegroundColor Yellow
    # Find the latest backup
    $backupFiles = Get-ChildItem "$env:TEMP\audit_settings_backup_*.xml" | Sort-Object LastWriteTime -Descending
    if ($backupFiles) {
        Restore-AuditSettings -BackupFile $backupFiles[0].FullName
    }
}

if (-not $ApplyChanges) {
    Write-Host "`n💡 TIP: Run with -ApplyChanges to actually test audit policy modifications" -ForegroundColor Cyan
    Write-Host "Example: .\Test-AuditScripts-Local.ps1 -ApplyChanges" -ForegroundColor White
}

Write-Host "`n✅ Local testing completed!" -ForegroundColor Green