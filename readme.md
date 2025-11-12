# Windows Event Auditing & MITRE ATT&CK Mapping

This repository provides comprehensive Windows security auditing scripts, testing tools, and MITRE ATT&CK framework mappings. It enables organizations to configure robust security logging, test event generation, and map Windows Event IDs to attack techniques for effective threat detection.

## Features

- **Audit Configuration Scripts**: Two PowerShell scripts to enable comprehensive Windows security logging
- **MITRE ATT&CK Mapping**: Complete mapping of Windows Event IDs to MITRE ATT&CK tactics and techniques
- **Testing Tools**: Scripts to verify audit configuration and event generation
- **Synthetic Log Generation**: Generate realistic test logs for SIEM testing and detection rule validation
- **Docker Container Testing**: Isolated Windows containers for reproducible, safe testing
- **CI/CD Integration**: GitHub Actions workflows for automated testing
- **Comprehensive Documentation**: Detailed Event ID reference and detection use cases

## Repository Structure

```
win-example-audit-mitre/
├── scripts/              # PowerShell scripts for audit configuration, testing, and log generation
│   ├── SysmonLikeAudit.ps1              # Comprehensive audit configuration
│   ├── win-audit.ps1                    # MITRE ATT&CK-guided audit configuration
│   ├── Test-EventIDGeneration.ps1       # Test and verify event generation
│   ├── Generate-SyntheticLogs.ps1       # Generate synthetic logs for testing
│   ├── Run-DockerTests.ps1              # Docker test runner
│   └── Local-DockerTest.ps1             # Local Docker testing helper
├── docs/                 # Documentation for Event IDs and MITRE mappings
│   ├── EVENT_IDS.md                     # Comprehensive Event ID reference
│   ├── MITRE_ATTACK_MAPPING.md          # MITRE ATT&CK to Event ID mappings
│   ├── DOCKER_TESTING.md                # Docker testing guide
│   ├── CI_CD.md                         # CI/CD integration guide
│   └── README.md                        # Documentation guide
├── .github/
│   └── workflows/        # GitHub Actions CI/CD workflows
│       ├── windows-docker-tests.yml     # Full test suite
│       └── pr-quick-test.yml            # Quick PR validation
├── examples/             # Example queries and detection rules (planned)
├── tests/                # Automated testing scripts (planned)
├── Dockerfile            # Windows Server Core container
├── docker-compose.yml    # Docker Compose configuration
└── readme.md             # This file
```

## Quick Start

### 1. Configure Audit Logging

Choose one of the audit configuration scripts based on your needs:

#### Option A: Comprehensive Logging (SysmonLikeAudit.ps1)
```powershell
# Run as Administrator
cd scripts
.\SysmonLikeAudit.ps1
```

**Best for:** Detailed forensic analysis, environments where storage is not a constraint

#### Option B: MITRE ATT&CK-Guided Logging (win-audit.ps1)
```powershell
# Run as Administrator
cd scripts
.\win-audit.ps1
```

**Best for:** Threat hunting, reduced false positives, MITRE ATT&CK-aligned detection

### 2. Test Your Configuration

Verify that events are being generated correctly:

```powershell
# Basic configuration check
.\Test-EventIDGeneration.ps1

# Full test with event generation
.\Test-EventIDGeneration.ps1 -TestEventGeneration -DetailedReport

# Export results for analysis
.\Test-EventIDGeneration.ps1 -TestEventGeneration -ExportResults
```

### 3. Generate Test Logs

Create synthetic logs for testing your SIEM and detection rules:

```powershell
# Generate credential dumping scenario
.\Generate-SyntheticLogs.ps1 -Scenario CredentialDumping -EventCount 100

# Generate comprehensive test data
.\Generate-SyntheticLogs.ps1 -Scenario All -IncludeNormalActivity -ExportFormat Both
```

## Docker Testing & CI/CD

### Docker Container Testing

Test audit configurations in isolated Windows containers for reproducible, safe testing:

```powershell
# Quick start - Build, run, and test everything
.\scripts\Local-DockerTest.ps1 -Action All

# Or use individual commands
.\scripts\Local-DockerTest.ps1 -Action Build    # Build Docker image
.\scripts\Local-DockerTest.ps1 -Action Run      # Start container
.\scripts\Local-DockerTest.ps1 -Action Test     # Run tests
.\scripts\Local-DockerTest.ps1 -Action Shell    # Interactive shell
.\scripts\Local-DockerTest.ps1 -Action Clean    # Cleanup
```

**Using Docker Compose**:
```powershell
# Start container
docker-compose up -d

# Run tests
docker-compose exec windows-audit-test powershell -File C:\workspace\scripts\Run-DockerTests.ps1

# Stop and remove
docker-compose down
```

**Benefits**:
- **Isolated Environment**: Test without affecting host system
- **Reproducible**: Consistent results across machines
- **Automated**: Full CI/CD integration with GitHub Actions
- **Safe Testing**: Run potentially risky tests in containers

See [docs/DOCKER_TESTING.md](docs/DOCKER_TESTING.md) for comprehensive Docker testing guide.

### GitHub Actions CI/CD

The repository includes automated testing workflows:

**Full Test Suite** (`windows-docker-tests.yml`):
- Triggered on push to main/develop or pull requests
- Builds Windows Docker container
- Runs parallel test suites (Audit Config, Event Generation, Synthetic Logs, Integration)
- Generates comprehensive test reports
- Posts results to pull requests

**Quick PR Test** (`pr-quick-test.yml`):
- Fast validation for pull requests
- PowerShell syntax checking
- Dockerfile validation
- Documentation checks

**Viewing Results**:
- Navigate to **Actions** tab in GitHub
- View detailed logs and test results
- Download test artifacts (JSON results, synthetic logs)
- See automated PR comments with test summaries

See [docs/CI_CD.md](docs/CI_CD.md) for CI/CD integration details and customization.

## Audit Configuration Scripts

### SysmonLikeAudit.ps1

Comprehensive Windows audit policy configuration providing Sysmon-like logging capabilities.

**Enables:**
- Object Access: Files, registry, kernel objects, SAM
- Process Creation: Full command-line logging
- Network Events: Filtering Platform connections and packet drops
- PowerShell: Module, script block, and transcription logging
- Log Settings: 32MB log sizes with overwrite policy

**Use when you need:**
- Maximum visibility for forensic investigations
- Comprehensive logging for incident response
- Detailed network activity monitoring

### win-audit.ps1

MITRE ATT&CK-guided audit configuration optimized for threat detection.

**Enables:**
- Success-only logging for noisy categories (reduced false positives)
- Directory Services auditing for domain environments
- Kerberos authentication tracking
- Focus on high-value security events

**Use when you need:**
- MITRE ATT&CK framework alignment
- Reduced log volume without sacrificing detection capability
- Optimized threat hunting configurations

## Testing & Validation

### Test-EventIDGeneration.ps1

Comprehensive testing script that validates audit configuration and verifies event generation.

**Features:**
- Validates all audit policy settings
- Checks PowerShell logging registry configurations
- Generates test events to verify logging
- Provides detailed coverage report
- Exports results to JSON

**Usage:**
```powershell
# Configuration check only
.\Test-EventIDGeneration.ps1

# Full validation with event generation
.\Test-EventIDGeneration.ps1 -TestEventGeneration -DetailedReport -ExportResults
```

### Generate-SyntheticLogs.ps1

Creates realistic Windows Security Event logs for testing SIEM rules and detection logic.

**Scenarios:**
- `CredentialDumping`: LSASS access, credential theft, Kerberos attacks
- `LateralMovement`: RDP, SMB, Pass-the-Hash, network logons
- `PrivilegeEscalation`: UAC bypass, token manipulation
- `Persistence`: Scheduled tasks, account creation, registry modifications
- `Reconnaissance`: System/network discovery, enumeration
- `DefenseEvasion`: Log tampering, obfuscated scripts
- `All`: Generate events for all scenarios

**Usage:**
```powershell
# Generate specific scenario
.\Generate-SyntheticLogs.ps1 -Scenario LateralMovement -EventCount 200

# Comprehensive test data
.\Generate-SyntheticLogs.ps1 -Scenario All -IncludeNormalActivity -TimeSpan 120
```

## Documentation

### [EVENT_IDS.md](docs/EVENT_IDS.md)
Comprehensive reference for all Windows Security Event IDs:
- Event descriptions organized by category
- Critical security events to monitor
- Event correlation patterns for threat detection
- Logon types and privilege reference
- Query examples and analysis tips

### [MITRE_ATTACK_MAPPING.md](docs/MITRE_ATTACK_MAPPING.md)
Complete mapping between Windows Event IDs and MITRE ATT&CK framework:
- Mapping tables organized by MITRE tactic
- Reverse lookup: Event ID to technique
- Detection use cases with example queries
- Coverage analysis and gaps identification
- 10+ detailed threat detection scenarios

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrator privileges
- Execution policy allowing script execution

## Use Cases

### For Security Engineers
1. Configure audit policies using provided scripts
2. Map detections to MITRE ATT&CK framework
3. Build and test detection rules with synthetic logs
4. Validate SIEM ingestion and parsing

### For Threat Hunters
1. Use MITRE mappings to identify relevant Event IDs for specific techniques
2. Reference detection use cases for hunting queries
3. Correlate events to identify attack chains
4. Test hunting hypotheses with synthetic data

### For Incident Responders
1. Reference Event ID documentation during investigations
2. Understand attacker TTPs through MITRE mappings
3. Reconstruct attack timelines using event correlations
4. Perform forensic analysis with comprehensive logging

### For Compliance & Audit
1. Demonstrate logging coverage for compliance frameworks
2. Map audit requirements to specific Event IDs
3. Show alignment with security standards (NIST, CIS, PCI-DSS)
4. Validate audit effectiveness with testing tools

## Critical Event IDs

For a complete list of Event IDs, see [docs/EVENT_IDS.md](docs/EVENT_IDS.md). Below are some of the most critical events for threat detection:

### High-Priority Events

| Event ID | Description | MITRE Tactics |
|----------|-------------|---------------|
| **4688** | Process Creation | Execution, Discovery, Lateral Movement |
| **4624** | Successful Logon | Initial Access, Lateral Movement |
| **4625** | Failed Logon | Initial Access (Brute Force) |
| **4672** | Special Privileges Assigned | Privilege Escalation |
| **4698** | Scheduled Task Created | Persistence, Execution |
| **4768** | Kerberos TGT Request | Credential Access (Golden Ticket) |
| **4769** | Kerberos Service Ticket | Credential Access (Kerberoasting) |
| **5140** | Network Share Accessed | Lateral Movement, Collection |
| **5156** | Network Connection Allowed | Command & Control, Exfiltration |
| **4657** | Registry Modified | Persistence, Defense Evasion |
| **4104** | PowerShell Script Block | Execution, Defense Evasion |

### Event Categories

**Process & Execution**
- 4688 (Process Creation), 4689 (Process Exit)
- 4103, 4104 (PowerShell Logging)
- 4698-4702 (Scheduled Tasks)

**Authentication & Access**
- 4624, 4625 (Logon Success/Failure)
- 4768, 4769, 4771 (Kerberos)
- 4776 (NTLM Authentication)

**Lateral Movement**
- 4624 Type 3, 10 (Network/RDP Logons)
- 5140, 5145 (File Share Access)
- 4648 (Explicit Credentials)

**Credential Access**
- 4656, 4663 (Object Access - LSASS, SAM)
- 5376, 5377 (Credential Manager)
- 4768, 4769 (Kerberos Attacks)

**Persistence & Privilege Escalation**
- 4698, 4702 (Scheduled Tasks)
- 4720, 4732 (Account Creation & Group Membership)
- 4657 (Registry Run Keys)
- 4697 (Service Installation)

For detailed information on each Event ID and detection use cases, see the [documentation](docs/).

## Best Practices

### Before Deploying

1. **Test in Non-Production Environment**
   - Deploy to test systems first
   - Monitor performance impact
   - Verify log volume and storage requirements

2. **Backup Current Configuration**
   ```powershell
   # Backup current audit policy
   auditpol /backup /file:audit_policy_backup.csv

   # Create system restore point
   Checkpoint-Computer -Description "Before Audit Policy Changes"
   ```

3. **Plan Log Management**
   - Calculate expected log volume (typically 50-200 MB/day per system)
   - Configure log forwarding to SIEM or log aggregator
   - Set appropriate retention policies

### After Deployment

1. **Verify Configuration**
   ```powershell
   # Run test script
   .\scripts\Test-EventIDGeneration.ps1 -TestEventGeneration

   # Check current audit policy
   auditpol /get /category:*
   ```

2. **Monitor Performance**
   - Check system CPU and disk I/O
   - Monitor event log sizes
   - Adjust audit policies if performance degrades

3. **Establish Baselines**
   - Document normal event rates
   - Identify typical user behavior patterns
   - Create allowlists for expected activities

4. **Configure SIEM Integration**
   - Set up log forwarding (Windows Event Forwarding, Syslog, etc.)
   - Create parsing rules for Event IDs
   - Build detection rules using MITRE mappings

## Troubleshooting

### Audit Policies Not Applying

**Issue**: Running scripts but events not being generated

**Solutions**:
```powershell
# Check if Group Policy is overriding local settings
gpresult /r /scope:computer

# Restart Windows Event Log service
Restart-Service EventLog

# Verify audit policies
auditpol /get /category:*
```

### High Log Volume

**Issue**: Event logs filling up too quickly

**Solutions**:
1. Use `win-audit.ps1` instead of `SysmonLikeAudit.ps1` (success-only logging)
2. Increase log sizes:
   ```powershell
   wevtutil sl Security /ms:67108864  # Set to 64MB
   ```
3. Configure log forwarding to external storage
4. Use filtering to exclude noisy events

### Performance Impact

**Issue**: System slowdown after enabling audit policies

**Solutions**:
1. Disable File System auditing (highest overhead)
2. Limit Object Access auditing to specific folders using SACLs
3. Use success-only logging for process creation
4. Increase event log sizes to reduce write frequency

### Events Not Showing in SIEM

**Issue**: Events generated but not appearing in SIEM

**Solutions**:
1. Verify log forwarding configuration
2. Check firewall rules for log forwarding ports
3. Validate SIEM parsing rules for Event IDs
4. Ensure proper authentication for log collection

## Advanced Configuration

### Selective File System Auditing

To audit specific directories without overwhelming logs:

```powershell
# Set SACL on specific folder
$acl = Get-Acl "C:\SensitiveData"
$audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "Write,Delete", "ContainerInherit,ObjectInherit", "None", "Success"
)
$acl.AddAuditRule($audit)
Set-Acl "C:\SensitiveData" $acl
```

### Centralized Logging with Windows Event Forwarding

Configure Windows Event Collector:

```powershell
# On collector server
wecutil qc

# Configure subscription (use XML config file)
wecutil cs subscription.xml
```

### Integration with Sysmon

Combine with Sysmon for additional telemetry:

1. Install Sysmon with SwiftOnSecurity config
2. Run audit configuration scripts
3. Forward both Security and Sysmon logs to SIEM

## Contributing

Contributions are welcome! Areas for contribution:

- **Detection Rules**: Add SIEM queries to `/examples`
- **Test Cases**: Expand test coverage in `/tests`
- **Documentation**: Improve Event ID descriptions and use cases
- **Scripts**: Enhance existing scripts or add new utilities
- **MITRE Mappings**: Suggest additional technique mappings

To contribute:
1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Test thoroughly on multiple Windows versions
5. Submit a pull request

## License

This project is provided as-is for security research, testing, and educational purposes.

## Acknowledgments

- MITRE ATT&CK framework for threat intelligence structure
- Microsoft Security documentation
- NSA Cybersecurity Guidance on Event Logging
- JPCERT Windows Event Log Analysis research
- SwiftOnSecurity's Sysmon configuration

## Additional Resources

- [Microsoft Advanced Security Audit Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Ultimate Windows Security](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [NSA Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance)
- [SANS Windows Forensics](https://www.sans.org/security-resources/posters/windows-forensic-analysis/)

## Support

For issues, questions, or suggestions:
- Open an issue in the GitHub repository
- Review existing documentation in `/docs`
- Check troubleshooting section above

---

**Version**: 2.0
**Last Updated**: 2025-11-11
