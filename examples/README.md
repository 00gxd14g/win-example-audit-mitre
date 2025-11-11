# Examples Directory

This directory contains example queries, detection rules, and use cases for Windows Security Event monitoring.

## Purpose

This directory is intended for:
- Example SIEM queries (Splunk, Elastic, Sentinel)
- Detection rule templates
- PowerShell query examples
- Event correlation patterns
- Sample reports and dashboards

## Coming Soon

Example content will include:

### Detection Rules
- Credential dumping detection
- Lateral movement patterns
- Privilege escalation indicators
- Persistence mechanism detection
- PowerShell abuse detection

### SIEM Queries

**Splunk Examples:**
```spl
index=windows EventCode=4688
| where (match(CommandLine, "(?i)mimikatz") OR match(CommandLine, "(?i)sekurlsa"))
| stats count by user, ComputerName, CommandLine
```

**Elastic/EQL Examples:**
```eql
sequence by user.name with maxspan=5m
  [authentication where event.outcome == "success" and winlog.logon.type == "Network"]
  [file where event.action == "access" and file.path : "C:\\Windows\\System32\\config\\SAM"]
```

**Microsoft Sentinel/KQL Examples:**
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine contains "lsass" or CommandLine contains "procdump"
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
```

### PowerShell Query Examples
```powershell
# Find recent process creation events with suspicious commands
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
    StartTime=(Get-Date).AddHours(-24)
} | Where-Object {
    $_.Message -match "mimikatz|procdump|lsass"
} | Select-Object TimeCreated, @{n='CommandLine';e={
    $_.Properties[8].Value
}}
```

### Hunting Queries

Example threat hunting queries for specific MITRE techniques:
- Pass-the-Hash detection
- Kerberoasting identification
- Golden/Silver Ticket detection
- Scheduled task persistence
- Registry run key persistence

## Contributing Examples

To add examples:
1. Create a subdirectory for the platform/tool (e.g., `splunk/`, `sentinel/`, `elastic/`)
2. Include working, tested queries
3. Add comments explaining the detection logic
4. Reference the MITRE ATT&CK technique
5. Include expected output or sample results
6. Document any prerequisites or dependencies

Example file structure:
```
examples/
├── splunk/
│   ├── credential_access.spl
│   ├── lateral_movement.spl
│   └── README.md
├── sentinel/
│   ├── analytic_rules.kql
│   └── workbooks.json
├── powershell/
│   ├── hunting_queries.ps1
│   └── forensic_scripts.ps1
└── README.md (this file)
```

## Related Documentation

- [../docs/MITRE_ATTACK_MAPPING.md](../docs/MITRE_ATTACK_MAPPING.md) - MITRE technique mappings
- [../docs/EVENT_IDS.md](../docs/EVENT_IDS.md) - Event ID reference
- [../scripts/](../scripts/) - Testing and synthetic log generation scripts
