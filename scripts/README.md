# Scripts Directory

This directory contains PowerShell scripts for Windows audit configuration, testing, and synthetic log generation.

## Audit Configuration Scripts

### SysmonLikeAudit.ps1
Comprehensive Windows audit policy configuration that provides Sysmon-like logging capabilities.

**Features:**
- Enables detailed object access auditing (files, registry, kernel objects)
- Configures process creation with command-line logging
- Sets up network monitoring (Filtering Platform events)
- Enables PowerShell advanced logging
- Configures event log sizes and retention

**Usage:**
```powershell
# Run as Administrator
.\SysmonLikeAudit.ps1
```

### win-audit.ps1
MITRE ATT&CK-guided Windows audit policy configuration optimized for reduced false positives.

**Features:**
- MITRE ATT&CK framework alignment
- Success-only logging for noisy categories
- Directory Services auditing for domain environments
- Optimized for threat hunting and detection
- Includes Turkish language comments

**Usage:**
```powershell
# Run as Administrator
.\win-audit.ps1
```

## Testing Scripts

### Test-EventIDGeneration.ps1
Comprehensive testing script to verify Windows audit configuration and event ID generation.

**Features:**
- Validates audit policy settings
- Checks registry configurations for PowerShell and process logging
- Generates test events to verify logging
- Queries event logs to confirm event creation
- Provides detailed coverage report
- Exports results to JSON for analysis

**Usage:**
```powershell
# Check configuration only
.\Test-EventIDGeneration.ps1

# Test with event generation
.\Test-EventIDGeneration.ps1 -TestEventGeneration -DetailedReport

# Export results
.\Test-EventIDGeneration.ps1 -TestEventGeneration -ExportResults
```

**Parameters:**
- `-TestEventGeneration`: Actively generate test events
- `-DetailedReport`: Provides verbose output for each test
- `-ExportResults`: Exports results to JSON file

### Generate-SyntheticLogs.ps1
Generates realistic synthetic Windows Security Event logs for testing SIEM rules and detection logic.

**Features:**
- Creates events mapped to MITRE ATT&CK techniques
- Simulates multiple attack scenarios
- Generates both suspicious and benign activity
- Exports to JSON, CSV formats
- Configurable event counts and time spans
- Includes detailed event metadata

**Usage:**
```powershell
# Generate credential dumping events
.\Generate-SyntheticLogs.ps1 -Scenario CredentialDumping -EventCount 50

# Generate comprehensive test data
.\Generate-SyntheticLogs.ps1 -Scenario All -IncludeNormalActivity -ExportFormat CSV

# Custom time span and output location
.\Generate-SyntheticLogs.ps1 -Scenario LateralMovement -TimeSpan 120 -OutputPath C:\Logs
```

**Parameters:**
- `-Scenario`: Attack scenario (CredentialDumping, LateralMovement, PrivilegeEscalation, Persistence, Reconnaissance, DefenseEvasion, All)
- `-EventCount`: Number of events to generate (default: 100)
- `-OutputPath`: Directory for output files (default: .\SyntheticLogs)
- `-TimeSpan`: Time range in minutes to spread events (default: 60)
- `-IncludeNormalActivity`: Mix in benign events
- `-ExportFormat`: Output format (JSON, CSV, Both)

**Supported Attack Scenarios:**
1. **CredentialDumping**: LSASS access, credential theft, Kerberos attacks
2. **LateralMovement**: RDP, SMB, network logons, pass-the-hash
3. **PrivilegeEscalation**: UAC bypass, token manipulation, privilege assignment
4. **Persistence**: Scheduled tasks, account creation, registry modifications
5. **Reconnaissance**: System/network discovery, enumeration commands
6. **DefenseEvasion**: Log tampering, obfuscated scripts, registry changes

## Requirements

All scripts require:
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrator privileges
- Execution policy set to allow scripts

## Best Practices

1. **Before Running Audit Scripts:**
   - Create a system restore point
   - Document current audit settings: `auditpol /backup /file:backup.csv`
   - Test in a non-production environment first

2. **Testing Event Generation:**
   - Run `Test-EventIDGeneration.ps1` after applying audit policies
   - Verify events are being logged before deploying to production
   - Monitor log sizes and adjust retention as needed

3. **Using Synthetic Logs:**
   - Use for testing detection rules in SIEM platforms
   - Validate incident response playbooks
   - Train security analysts on event analysis
   - Never mix synthetic logs with production data

## Troubleshooting

**Audit policies not applying:**
- Verify Administrator privileges
- Check Group Policy isn't overriding local settings
- Restart Windows Event Log service: `Restart-Service EventLog`

**Events not being generated:**
- Verify audit policies with: `auditpol /get /category:*`
- Check event log sizes aren't full
- Verify registry settings for PowerShell logging

**Test script shows failures:**
- Review specific failed tests in output
- Re-run audit configuration scripts
- Check for conflicting Group Policy Objects (GPO)

## Related Documentation

- [../docs/EVENT_IDS.md](../docs/EVENT_IDS.md) - Comprehensive Event ID reference
- [../docs/MITRE_ATTACK_MAPPING.md](../docs/MITRE_ATTACK_MAPPING.md) - MITRE ATT&CK to Event ID mappings
- [../readme.md](../readme.md) - Project overview

## Contributing

When adding new scripts:
1. Include comprehensive help documentation
2. Add parameter validation and error handling
3. Test on multiple Windows versions
4. Update this README with usage examples
5. Add corresponding documentation in `/docs` if needed
